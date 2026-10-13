package group

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/schedule"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Building a Welcome (RFC 9420 sections 12.4.2 and 12.4.3.1).
//
// The steps, from the specification:
//
//	* For each new member in the group:
//	    - Identify the lowest common ancestor in the tree of the new member's leaf node and
//	      the member sending the Commit
//	    - If the path field was populated above: Compute the path secret corresponding to the
//	      common ancestor node
//	    - Compute an EncryptedGroupSecrets object that encapsulates the joiner_secret for the
//	      current epoch and the path secret (if present)
//	* Construct one or more Welcome messages from the encrypted GroupInfo object, the
//	  encrypted key packages, and any PSKs ...
//
// # The word in the third step that has to be resolved before anything is written
//
// That step says "the init_secret for the current epoch" in one draft revision, while the
// structure's field is named joiner_secret. They are different values in this implementation
// and the difference is verified against the official key-schedule vectors. It is settled by
// what the NEW MEMBER DOES with it (section 12.4.3.1):
//
//	From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in the
//	GroupSecrets, derive the welcome_secret and using that the welcome_key and welcome_nonce.
//	Use the key and nonce to decrypt the encrypted_group_info field.
//
// Deriving the welcome secret from it by mixing in the PSKs is exactly what the key schedule
// does with the joiner secret, so the value is the joiner secret and the other wording is
// stale. Getting this wrong would make every Welcome fail, and the failure would look like a
// decryption problem rather than a wrong input.
//
// # The GroupInfo ciphertext is an input here
//
// The GroupInfo must be encrypted before the group secrets can be, because its CIPHERTEXT is
// the HPKE context that binds them (section 12.4.3.1). The AEAD call itself is left to the
// caller so that this package does not have to guess an AEAD interface; the order, which is the
// part that must not be got wrong, is enforced by taking the ciphertext as a parameter.

// WelcomeKeyNonce derives the key and nonce that protect a Welcome's GroupInfo.
//
//	welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", AEAD.Nn)
//	welcome_key   = ExpandWithLabel(welcome_secret, "key",   "", AEAD.Nk)
//
// Two details here are easy to get wrong and both come from the text: the labels are "key" and
// "nonce" rather than anything containing the word welcome, and the lengths are the AEAD's key
// and nonce sizes rather than the hash length used by every other derivation in the protocol.
func WelcomeKeyNonce(welcomeSecret []byte, suite crypto.CipherSuite) (key, nonce []byte, err error) {
	if len(welcomeSecret) != suite.HashSize() {
		return nil, nil, fmt.Errorf("mls/group: the welcome secret is %d bytes, want %d",
			len(welcomeSecret), suite.HashSize())
	}

	key, err = crypto.ExpandWithLabel(welcomeSecret, "key", []byte{}, suite.AEADKeySize(), suite)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = crypto.ExpandWithLabel(welcomeSecret, "nonce", []byte{}, suite.AEADNonceSize(), suite)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// NewMember is one member a commit is adding.
type NewMember struct {
	// LeafIndex is where the commit placed the member's leaf.
	LeafIndex uint32

	// InitKey is the member's init key from its KeyPackage: the key its Welcome is encrypted to,
	// which is deliberately not the key its leaf carries.
	InitKey []byte

	// KeyPackageRef identifies the KeyPackage this member was added from, so a receiver can tell
	// which entry of the Welcome is its own.
	KeyPackageRef messages.KeyPackageRef
}

// WelcomeSpec is everything needed to build a Welcome.
type WelcomeSpec struct {
	Suite crypto.CipherSuite

	// CommitterLeaf is the leaf index of the member that made the commit.
	CommitterLeaf uint32

	// NewMembers are the members the commit added, in any order.
	NewMembers []NewMember

	// PathSecretsByNode holds the committer's update path secrets, keyed by node index.
	PathSecretsByNode map[uint32][]byte

	// LeafCount is the NEW tree's leaf count, after the commit. The lowest common ancestor is
	// computed in that tree, because that is the tree the new member is joining.
	LeafCount uint32

	// NewEpochSecrets are the epoch's secrets, whose JoinerSecret is what the Welcome delivers.
	NewEpochSecrets schedule.EpochSecrets

	// EncryptedGroupInfo is the GroupInfo for the new epoch, already encrypted under the key and
	// nonce from WelcomeKeyNonce. Its ciphertext is the HPKE context for every entry, so it has
	// to exist first — which is why it is passed in rather than produced here.
	EncryptedGroupInfo []byte

	// PSKs are the pre-shared keys the commit injected, in the order the commit listed them.
	PSKs []schedule.PSK
}

// BuildWelcome assembles the Welcome for a commit that added members.
func BuildWelcome(spec WelcomeSpec) (*messages.Welcome, error) {
	if len(spec.NewMembers) == 0 {
		return nil, fmt.Errorf("mls/group: a Welcome needs at least one new member")
	}
	if len(spec.EncryptedGroupInfo) == 0 {
		return nil, fmt.Errorf("mls/group: a Welcome needs the encrypted GroupInfo: its ciphertext " +
			"is the HPKE context that binds the group secrets to it")
	}
	if len(spec.NewEpochSecrets.JoinerSecret) == 0 {
		return nil, fmt.Errorf("mls/group: the epoch's joiner secret is empty; it is what the " +
			"Welcome delivers and what every new member's epoch derives from")
	}

	psks, err := pskIDsFor(spec.PSKs, spec.Suite)
	if err != nil {
		return nil, err
	}

	welcome := &messages.Welcome{
		CipherSuite:        uint16(spec.Suite),
		EncryptedGroupInfo: spec.EncryptedGroupInfo,
	}

	for _, member := range spec.NewMembers {
		if len(member.InitKey) == 0 {
			return nil, fmt.Errorf("mls/group: the new member at leaf %d has no init key, so its "+
				"Welcome cannot be encrypted to it", member.LeafIndex)
		}

		// The path secret of the LOWEST node on both the committer's and the new member's direct
		// paths. Everything above it is derivable from it and everything below it is the member's
		// own, which is what makes that one node the only thing it cannot work out itself.
		ancestor, pathSecret, present, err := tree.PathSecretForNewMember(
			2*spec.CommitterLeaf, 2*member.LeafIndex, spec.LeafCount, spec.PathSecretsByNode)
		if err != nil {
			return nil, err
		}
		_ = ancestor

		secrets := &messages.GroupSecrets{
			JoinerSecret: spec.NewEpochSecrets.JoinerSecret,
			PSKs:         psks,
		}
		if present {
			secrets.PathSecret = &messages.PathSecret{PathSecret: pathSecret}
		}
		// When the ancestor carries no secret the field is OMITTED, not written empty: the two
		// encode differently, and a new member that read an empty secret as a present one would
		// derive a different epoch from everybody else.

		sealed, err := messages.EncryptGroupSecrets(member.InitKey, spec.EncryptedGroupInfo,
			secrets, spec.Suite)
		if err != nil {
			return nil, fmt.Errorf("mls/group: sealing the secrets for the member at leaf %d: %w",
				member.LeafIndex, err)
		}

		welcome.Secrets = append(welcome.Secrets, messages.EncryptedGroupSecrets{
			NewMember:             member.KeyPackageRef,
			EncryptedGroupSecrets: sealed,
		})
	}

	return welcome, nil
}

// pskIDsFor turns the epoch's PSKs into the identifiers a Welcome lists.
//
// The ORDER matters and is the commit's: the specification requires the Welcome's psks to be in
// the same order as the PreSharedKey proposals, because the joiner mixes them in that order and
// a different order produces a different epoch secret.
func pskIDsFor(psks []schedule.PSK, suite crypto.CipherSuite) ([]messages.PreSharedKeyID, error) {
	out := make([]messages.PreSharedKeyID, 0, len(psks))
	for _, psk := range psks {
		if len(psk.ID) == 0 || len(psk.Nonce) == 0 {
			return nil, fmt.Errorf("mls/group: a PSK in the Welcome has no id or no nonce")
		}
		out = append(out, messages.PreSharedKeyID{
			Type:  messages.PSKTypeExternal,
			ID:    psk.ID,
			Nonce: psk.Nonce,
		})
	}
	_ = suite
	return out, nil
}
