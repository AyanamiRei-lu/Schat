package mobile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/group"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Adding a member, from the binding.
//
// # Where a member's own leaf index comes from
//
// The group's state does not record which leaf belongs to the local member, and adding one would
// be a second place for the client to keep in step with the tree. It is found instead, by
// scanning the leaves for the identity's signing key — the same key that identifies this member
// to its contacts. A scan is cheap (leaves are even-indexed, and a group is not large) and it
// cannot drift out of step with the tree, because the tree is what it reads.
//
// # What has to happen before the Welcome can be built
//
// The GroupInfo is encrypted FIRST, with the key and nonce the welcome secret produces, because
// its CIPHERTEXT is the HPKE context that binds every member's group secrets to it. Building the
// Welcome before the GroupInfo exists is therefore impossible rather than merely out of order,
// and the code below is arranged to make that visible.

// GroupAddResult is what an add produces: the new state, the commit to broadcast, and the
// Welcome to deliver to the member being added.
type GroupAddResult struct {
	// StateJSON is the committer's state AFTER the commit, ready to be stored.
	StateJSON string

	// CommitHex is the commit, to be sent to every member already in the group.
	CommitHex string

	// WelcomeHex is the Welcome, to be sent to the member being added.
	WelcomeHex string
}

// GroupAddMember adds a member, given that member's published KeyPackage.
//
// The KeyPackage's signature IS verified here. It has to be: the leaf it carries becomes part of
// the group, and a KeyPackage whose signature does not check is one that could name an identity
// other than the one that produced it — which is precisely the substitution the group's whole
// membership story rests on.
func GroupAddMember(stateJSON, identityJSON, keyPackageHex string) (*GroupAddResult, error) {
	identity, err := IdentityFromJSON(identityJSON)
	if err != nil {
		return nil, err
	}

	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return nil, err
	}

	suite := crypto.CipherSuite(GroupCipherSuite)

	keyPackageBytes, err := hex.DecodeString(keyPackageHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the KeyPackage is not hex: %w", err)
	}
	keyPackage, err := messages.ParseKeyPackage(mlstls.NewReader(keyPackageBytes))
	if err != nil {
		return nil, fmt.Errorf("schat: the KeyPackage does not parse: %w", err)
	}
	if err := messages.VerifyKeyPackage(keyPackage, 1, GroupCipherSuite, suite); err != nil {
		return nil, fmt.Errorf("schat: refusing to add a member whose KeyPackage does not verify: %w", err)
	}

	myLeaf, err := findMyLeaf(epoch, identity)
	if err != nil {
		return nil, err
	}

	signingKey, err := hex.DecodeString(identity.SigningPrivate)
	if err != nil {
		return nil, fmt.Errorf("schat: the identity's signing key is not hex: %w", err)
	}

	// The committer replaces its own leaf as part of the commit: an Add on its own would leave
	// the sender's key in place, and the update is what removes the previous epoch's secrets
	// from the reach of anyone who later compromises the member.
	// The commit replaces the sender's OWN leaf, so the new key pair is generated here and its
	// private half is kept. A sender that discarded it would hold a key its leaf no longer
	// publishes — able to send this commit and unable to follow the next one from anybody else.
	newLeafSeed := make([]byte, 32)
	if _, err := rand.Read(newLeafSeed); err != nil {
		return nil, err
	}
	newLeafPrivate, newLeafPublic, err := crypto.DeriveKeyPair(newLeafSeed, suite)
	if err != nil {
		return nil, err
	}
	newLeaf, err := leafNodeFor(identity, newLeafPublic)
	if err != nil {
		return nil, err
	}
	newLeaf.Source = tree.LeafNodeSourceUpdate

	pathSecret := make([]byte, suite.HashSize())
	commitSecret := make([]byte, suite.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		return nil, err
	}
	if _, err := rand.Read(commitSecret); err != nil {
		return nil, err
	}

	created, err := epoch.CreateCommit(group.CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       myLeaf,
		SenderSigningKey: signingKey,
		Proposals: []*messages.ProposalOrRef{{
			Type:     messages.ProposalOrRefTypeProposal,
			Proposal: &messages.Proposal{Type: messages.ProposalTypeAdd, Add: &messages.Add{KeyPackage: keyPackage}},
		}},
		NewLeafNode:    newLeaf,
		NewLeafPrivate: newLeafPrivate,
		PathSecret:     pathSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("schat: building the commit: %w", err)
	}

	commitHex, err := encodeCommit(created)
	if err != nil {
		return nil, err
	}

	// A commit that cites an Add must have placed it; if it did not, the Welcome below would be
	// built for a member the tree does not contain.
	if len(created.AddedLeaves) == 0 {
		return nil, fmt.Errorf("schat: the commit added nobody, so there is no Welcome to send")
	}
	newMemberLeaf := created.AddedLeaves[0]

	// The GroupInfo for the NEW epoch, then its encryption, then the Welcome — in that order,
	// because the encrypted GroupInfo is the context the group secrets are bound to.
	contextBytes, err := created.Next.Context.Marshal()
	if err != nil {
		return nil, err
	}

	// The ratchet tree goes into the GroupInfo, because the Welcome carries no other way for a
	// new member to learn who is in the group. Without it the member would hold the epoch's keys
	// and not know whose messages they open.
	ratchetTree, err := tree.RatchetTreeExtension(created.Next.Tree)
	if err != nil {
		return nil, err
	}

	groupInfo := &messages.GroupInfo{
		GroupContext:    contextBytes,
		Extensions:      []tree.Extension{ratchetTree},
		ConfirmationTag: created.ConfirmationTag,
		Signer:          myLeaf,
	}
	signature, err := messages.SignGroupInfo(groupInfo, signingKey)
	if err != nil {
		return nil, fmt.Errorf("schat: signing the GroupInfo: %w", err)
	}
	groupInfo.Signature = signature

	groupInfoBytes, err := messages.MarshalGroupInfo(groupInfo)
	if err != nil {
		return nil, err
	}

	welcomeKey, welcomeNonce, err := group.WelcomeKeyNonce(created.Next.Secrets.WelcomeSecret, suite)
	if err != nil {
		return nil, err
	}
	encryptedGroupInfo, err := aesGCMSeal(welcomeKey, welcomeNonce, groupInfoBytes)
	if err != nil {
		return nil, fmt.Errorf("schat: encrypting the GroupInfo: %w", err)
	}

	keyPackageRef, err := messages.MakeKeyPackageReference(keyPackage, suite)
	if err != nil {
		return nil, err
	}

	leaves := uint32((len(created.Next.Tree) + 1) / 2)
	welcome, err := group.BuildWelcome(group.WelcomeSpec{
		Suite:         suite,
		CommitterLeaf: myLeaf,
		NewMembers: []group.NewMember{{
			LeafIndex:     newMemberLeaf,
			InitKey:       keyPackage.InitKey,
			KeyPackageRef: keyPackageRef,
		}},
		PathSecretsByNode:  created.KnownSecrets,
		LeafCount:          leaves,
		NewEpochSecrets:    created.Next.Secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	})
	if err != nil {
		return nil, fmt.Errorf("schat: building the Welcome: %w", err)
	}

	welcomeBytes, err := messages.MarshalWelcome(welcome)
	if err != nil {
		return nil, err
	}

	nextState, err := created.Next.Snapshot()
	if err != nil {
		return nil, err
	}

	return &GroupAddResult{
		StateJSON:  string(nextState),
		CommitHex:  commitHex,
		WelcomeHex: hex.EncodeToString(welcomeBytes),
	}, nil
}

// findMyLeaf returns the leaf index this identity occupies.
func findMyLeaf(epoch *group.Epoch, identity *Identity) (uint32, error) {
	if epoch == nil {
		return 0, fmt.Errorf("schat: no group state")
	}
	want, err := hex.DecodeString(identity.SigningPublic)
	if err != nil {
		return 0, fmt.Errorf("schat: the identity's signing key is not hex: %w", err)
	}

	// Leaves are at even indices in the array layout, so this walks the members and not the
	// internal nodes.
	for node := 0; node < len(epoch.Tree); node += 2 {
		holder := epoch.Tree[node]
		if holder == nil || holder.Leaf == nil {
			continue
		}
		if string(holder.Leaf.SignatureKey) == string(want) {
			return uint32(node / 2), nil
		}
	}
	return 0, fmt.Errorf("schat: this identity does not occupy any leaf of the group, so it " +
		"cannot commit to it")
}

// encodeCommit renders a commit for sending.
//
// The commit travels as an AuthenticatedContent: the framed content together with the signature
// over it and, for a commit, the confirmation tag. A receiver that had only the content could
// not check that the commit came from the member it claims.
func encodeCommit(created *group.CreatedCommit) (string, error) {
	authenticated := messages.AuthenticatedContent{
		WireFormat: created.WireFormat,
		Content:    *created.Content,
		Auth: messages.FramedContentAuthData{
			Signature:       created.Signature,
			ConfirmationTag: created.ConfirmationTag,
		},
	}

	w := mlstls.NewWriter(512)
	if err := authenticated.Marshal(w); err != nil {
		return "", err
	}
	if err := w.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(w.Bytes()), nil
}

// aesGCMSeal and aesGCMOpen are the suite's AEAD, used for the GroupInfo.
//
// The MLS suite this build uses is AES-128-GCM, so the standard library is the implementation
// rather than a reimplementation of it.
func aesGCMSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func aesGCMOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
