package group

import (
	"bytes"
	"crypto/ecdh"
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/schedule"
	mlstls "github.com/schat/schat/protocol/mls/tls"
	"github.com/schat/schat/protocol/mls/tree"
)

// Joining a group through a Welcome (RFC 9420 section 12.4.3.1).
//
// # The order is forced at every step
//
//	1. open your entry          -> the group secrets, which hold the joiner secret
//	2. joiner secret + PSKs     -> the welcome secret
//	3. welcome secret           -> key and nonce
//	4. key and nonce            -> the GroupInfo, and with it the GroupContext
//	5. joiner secret + PSKs + GroupContext -> the epoch's secrets
//	6. those secrets            -> the confirmation key, which checks the GroupInfo's tag
//
// Steps 2 and 5 both use the joiner secret and the PSKs, and the reason they are two steps is
// the GroupContext: it lives inside the GroupInfo, the GroupInfo is encrypted under a key
// derived from the welcome secret, and the welcome secret does not need the context. So the
// context cannot be had before step 4, and the epoch secret cannot be computed before step 5.
//
// # What this does NOT do
//
// It does not verify the GroupInfo's SIGNATURE. That needs the signer's public key, which comes
// from the signer's leaf in the ratchet tree, and deciding whether to trust a leaf is the
// membership question the caller owns. The confirmation tag IS checked, because it needs no key
// the caller has to supply and it is the check that proves the sender computed this epoch.
//
// It also does not build the ratchet tree: the caller supplies it, having taken it from the
// GroupInfo's ratchet_tree extension. A joiner that skipped that would have the epoch's keys
// and no idea who is in the group.

// AcceptWelcomeSpec is what a member needs to process its own entry of a Welcome.
type AcceptWelcomeSpec struct {
	Suite crypto.CipherSuite

	// Welcome is the message as received.
	Welcome *messages.Welcome

	// Entry is the member's own entry, found by matching NewMember against its KeyPackageRef.
	Entry messages.EncryptedGroupSecrets

	// InitKeyPrivate is the private half of the init key in its KeyPackage.
	InitKeyPrivate []byte

	// PSKs are the secrets for the identifiers listed in the group secrets, in the SAME order.
	// An empty slice is correct when the commit injected none.
	PSKs []schedule.PSK

	// Tree is the ratchet tree for the new epoch, from the GroupInfo's ratchet_tree extension.
	Tree tree.Tree

	// DecryptGroupInfo performs the AEAD opening of the GroupInfo under the derived key and
	// nonce. It is a callback because the AEAD interface belongs to the crypto package.
	DecryptGroupInfo func(key, nonce, ciphertext []byte) ([]byte, error)

	// MyLeafIndex and MyLeafPrivate are the member's own leaf and the private half of the
	// key it published in its KeyPackage. They are what make the joining member able to
	// FOLLOW the group rather than merely read it once.
	//
	// Section 12.4.3.1: "Update the leaf my_leaf with the private key corresponding to
	// the public key in the node." The public key in the node is this KeyPackage's leaf key,
	// which is why the private half had to be kept rather than discarded.
	MyLeafIndex   uint32
	MyLeafPrivate []byte
}

// JoinedGroup is the state a member has after accepting a Welcome.
type JoinedGroup struct {
	Epoch         *Epoch
	GroupInfo     *messages.GroupInfo
	WelcomeSecret []byte
}

// AcceptWelcome processes a Welcome and returns the joiner's epoch.
func AcceptWelcome(spec AcceptWelcomeSpec) (*JoinedGroup, error) {
	if spec.Welcome == nil {
		return nil, fmt.Errorf("mls/group: no Welcome")
	}
	if len(spec.InitKeyPrivate) == 0 {
		return nil, fmt.Errorf("mls/group: no init key private half; the Welcome is encrypted to it")
	}
	if spec.DecryptGroupInfo == nil {
		return nil, fmt.Errorf("mls/group: no way to open the GroupInfo, which is where the group " +
			"context comes from")
	}

	// 1. The member's own entry, using the GroupInfo's ciphertext as the HPKE context — the
	// binding the specification requires, and the reason this call takes the whole Welcome.
	groupSecrets, err := messages.DecryptGroupSecrets(spec.InitKeyPrivate,
		spec.Welcome.EncryptedGroupInfo, spec.Entry.EncryptedGroupSecrets, spec.Suite)
	if err != nil {
		return nil, err
	}

	// 2. The PSK secret, from the secrets the caller matched to the identifiers listed.
	pskSecret, err := schedule.PSKSecret(spec.PSKs, spec.Suite)
	if err != nil {
		return nil, err
	}

	// 3. The welcome secret, which does not need the group context.
	welcomeSecret, err := schedule.WelcomeSecretFromJoiner(groupSecrets.JoinerSecret, pskSecret, spec.Suite)
	if err != nil {
		return nil, err
	}

	// 4. The key and nonce, then the GroupInfo, then the context.
	welcomeKey, welcomeNonce, err := WelcomeKeyNonce(welcomeSecret, spec.Suite)
	if err != nil {
		return nil, err
	}

	groupInfoBytes, err := spec.DecryptGroupInfo(welcomeKey, welcomeNonce, spec.Welcome.EncryptedGroupInfo)
	if err != nil {
		return nil, fmt.Errorf("mls/group: opening the GroupInfo: %w", err)
	}

	groupInfo, err := messages.ParseGroupInfo(mlstls.NewReader(groupInfoBytes))
	if err != nil {
		return nil, fmt.Errorf("mls/group: parsing the GroupInfo: %w", err)
	}

	groupContext, err := schedule.ParseGroupContextBytes(groupInfo.GroupContext)
	if err != nil {
		return nil, err
	}
	if groupContext.CipherSuite != uint16(spec.Suite) {
		return nil, fmt.Errorf("mls/group: the GroupInfo is for cipher suite %#04x and this member "+
			"joined with %#04x", groupContext.CipherSuite, uint16(spec.Suite))
	}

	// 5. The epoch's secrets, now that the context exists.
	secrets, _, err := schedule.SecretsFromJoinerSecret(groupSecrets.JoinerSecret, pskSecret,
		groupContext, spec.Suite)
	if err != nil {
		return nil, err
	}

	// 6. The confirmation tag, which is the check that the sender computed this epoch. It needs
	// no key from the caller, so it is done here rather than left to them.
	if len(groupInfo.ConfirmationTag) == 0 {
		return nil, fmt.Errorf("mls/group: the GroupInfo carries no confirmation tag, so the " +
			"sender's epoch was never confirmed")
	}
	wantTag, err := messages.ConfirmationTag(secrets.ConfirmationKey,
		groupContext.ConfirmedTranscriptHash, spec.Suite)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(wantTag, groupInfo.ConfirmationTag) {
		return nil, fmt.Errorf("mls/group: the GroupInfo's confirmation tag does not match the " +
			"epoch these secrets produce, so the sender derived different group state")
	}

	// The ratchet tree, if the caller did not supply one.
	//
	// It cannot be supplied in the ordinary case: the joiner's tree arrives INSIDE this very
	// message, in the GroupInfo's ratchet_tree extension. Requiring the caller to pass it made
	// this function unusable by the only party that calls it — a mistake that a test passing
	// the committer's own tree could not reveal.
	//
	// Taking it from the GroupInfo costs nothing in safety, because the check below is what
	// makes the tree trustworthy: whatever the source, it must hash to the tree_hash in the
	// context that arrived with it. A forged tree fails there and not here.
	if len(spec.Tree) == 0 {
		fromExtension, found, err := tree.FindRatchetTree(groupInfo.Extensions)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("mls/group: the GroupInfo carries no ratchet tree, so this " +
				"member would hold the epoch's keys without knowing who is in the group")
		}
		spec.Tree = fromExtension
	}

	// The tree has to describe the same epoch the context does, or the member would hold keys
	// for one tree and a context for another.
	treeHash, err := treeHashOf(spec.Tree, spec.Suite)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(treeHash, groupContext.TreeHash) {
		return nil, fmt.Errorf("mls/group: the supplied ratchet tree does not hash to the tree " +
			"hash in the GroupInfo, so it is not this epoch's tree")
	}

	// The private keys along this member's own direct path (section 12.4.3.1), derived by the
	// shared function so that the welcome path and the commit path cannot disagree.
	var pathSecret []byte
	if groupSecrets.PathSecret != nil {
		pathSecret = groupSecrets.PathSecret.PathSecret
	}

	// WHERE THE JOINER IS, DERIVED RATHER THAN SUPPLIED.
	//
	// A member cannot know its own leaf index before joining: the only place that number exists
	// is the group's tree, and the only thing that identifies the member in that tree is the
	// public half of the key whose private half it just used to open the Welcome. Both are in
	// hand here, so the index is computed.
	//
	// It is not bookkeeping. The index decides which encrypted path secret the member tries to
	// open: with the wrong one it decrypts a secret addressed to somebody else, rebuilds a tree
	// that is not the group's, and fails at the CONFIRMATION TAG — a symptom that points at the
	// key schedule rather than at a wrong number.
	// With the leaf key in hand the index is DERIVED and any value the caller supplied is
	// ignored — the caller cannot know it, and a wrong one makes the member decrypt a secret
	// addressed to somebody else and fail later at the confirmation tag.
	//
	// WITHOUT the key there is nothing to derive from. The caller's value is then the only one
	// available, and a caller that has neither is caught here rather than left to guess: this is
	// the case a caller is in when it never kept the private half, which is exactly the gap that
	// made joining members unable to follow commits.
	if len(spec.MyLeafPrivate) > 0 {
		derived, err := findLeafByEncryptionKey(spec.Tree, spec.MyLeafPrivate, spec.Suite)
		if err != nil {
			return nil, err
		}
		spec.MyLeafIndex = derived
	} else if len(spec.Tree) == 0 {
		return nil, fmt.Errorf("mls/group: no leaf private key and no tree, so the joining " +
			"member's position cannot be established at all")
	}

	privateNodes, err := derivePrivateNodes(spec.Tree, spec.MyLeafIndex, groupInfo.Signer,
		spec.MyLeafPrivate, pathSecret, spec.Suite)
	if err != nil {
		return nil, err
	}

	// The joining member's interim transcript hash is the hash of the confirmation tag, not
	// the tag itself: the transcript advances by hashing that tag into the transcript, so a
	// member that used the raw tag would compute every later tag differently from everybody
	// else — and could never apply a commit.
	// Section 8.2, verbatim: "An interim_transcript_hash that covers the confirmed transcript
	// hash plus the confirmation_tag of the most recent Commit", and "New members compute the
	// interim transcript hash using the confirmation_tag field of the GroupInfo struct".
	//
	// So it is the hash of BOTH, concatenated — not the hash of the tag alone, which is what an
	// earlier version hashed. That version used the right tag and too little of it, and the
	// result was a member that agreed with the group about the confirmed hash and disagreed
	// about the interim one, and could therefore never apply a commit.
	// The confirmation tag enters as an ENCODED FIELD, not as raw bytes: the specification's "||"
	// in a presentation-language structure means the field's encoding, which for `opaque
	// confirmation_tag<V>` carries a length prefix. Two earlier attempts each supplied half of
	// this — the tag without the confirmed hash, then the confirmed hash with a raw tag — and
	// each produced a value that was plausible and wrong.
	interimInput, err := messages.InterimTranscriptHashInput(groupInfo.ConfirmationTag)
	if err != nil {
		return nil, err
	}
	interimHash := spec.Suite.Hash(concat(groupContext.ConfirmedTranscriptHash, interimInput))

	return &JoinedGroup{
		GroupInfo:     groupInfo,
		WelcomeSecret: welcomeSecret,
		Epoch: &Epoch{
			Number:    groupContext.Epoch,
			Suite:     spec.Suite,
			Tree:      spec.Tree,
			Context:   groupContext,
			Secrets:   secrets,
			Proposals: messages.NewProposalCache(spec.Suite),
			// A joining member's transcript does NOT start empty. The confirmed hash is the one
			// in the group context it just received, and the interim hash is the GroupInfo's
			// confirmation tag — the moment the group's state was confirmed, which is what
			// "the transcript as last confirmed" means for somebody who was not there for it.
			//
			// Starting empty made every later confirmation tag mismatch: the member computed
			// its tags over an empty transcript while everybody else computed them over the
			// real one, so a member that joined through a Welcome could never apply a single
			// commit. This is also why a GroupInfo carries a confirmation tag at all.
			Transcript: messages.Transcript{
				Confirmed: groupContext.ConfirmedTranscriptHash,
				Interim:   interimHash,
			},

			PrivateNodes: privateNodes,
		},
	}, nil
}

// findLeafByEncryptionKey locates the leaf whose public key matches the private key given.
//
// The tree is the joiner's copy of the group's ratchet tree, and the private key is the one from
// the KeyPackage that was added. Matching them is the only sound way to learn the leaf index:
// every alternative is a guess, and a wrong guess fails somewhere else entirely.
func findLeafByEncryptionKey(t tree.Tree, privateKey []byte, suite crypto.CipherSuite) (uint32, error) {
	if len(privateKey) == 0 {
		return 0, fmt.Errorf("mls/group: cannot locate the joining member's leaf without its " +
			"leaf private key")
	}
	// X25519 SCALAR MULTIPLICATION, not DeriveKeyPair. DeriveKeyPair takes an ikm to derive FROM,
	// so passing a private key to it produces an unrelated key pair — a mistake that has already
	// cost this project a long detour once, and whose symptom is "the tree does not contain this
	// member" when the tree contains it perfectly well.
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return 0, fmt.Errorf("mls/group: the joining member's leaf key is not a valid X25519 "+
			"scalar: %w", err)
	}
	public := priv.PublicKey().Bytes()
	for node := 0; node < len(t); node += 2 {
		if t[node] == nil || t[node].Leaf == nil {
			continue
		}
		if bytes.Equal(t[node].Leaf.EncryptionKey, public) {
			return uint32(node / 2), nil
		}
	}
	return 0, fmt.Errorf("mls/group: the group's tree holds no leaf for the key this member was " +
		"added with, so it is not in the group it is trying to join")
}
