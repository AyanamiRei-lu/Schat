package mobile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/group"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Group support across the binding.
//
// # Why this is a second, separate world from the one-to-one session
//
// The one-to-one protocol in session.go is SCS-1, this project's own construction. Groups use
// MLS, which is a different protocol with its own identity keys in a different role: an MLS
// member signs with an Ed25519 key and receives HPKE keys, and the group's state is a ratchet
// tree rather than a pair of ratchets.
//
// What the two share is the IDENTITY — the same long-term Ed25519 key identifies a member in
// both — so a contact that was verified once is verified in a group too.
//
// # What crosses the binding
//
// Strings and byte slices only, and group state crosses as the JSON snapshot that
// group.Epoch.Snapshot produces. That snapshot contains the epoch's keys, so the Kotlin side
// must store it inside its encrypted vault; this package says so and cannot enforce it.
//
// # What is NOT here yet
//
// Sending and receiving group messages through the relay. The pieces exist — the envelope
// content type for a group frame, and the sealing and opening in the group package — and what
// remains is the client-side wiring, which belongs with the rest of the relay code rather than
// here.

// GroupCipherSuite is the MLS suite this build uses.
//
// One suite only, and deliberately: suites 0x0002, 0x0005 and 0x0006 sign with ECDSA, which
// this implementation refuses rather than pretends to support. Offering a choice that fails
// later would be worse than offering none.
const GroupCipherSuite = 0x0001

// GroupSummary is a readable view of a group, so that the client can show something without
// parsing the snapshot.
type GroupSummary struct {
	// GroupIDHex is the group's identifier.
	GroupIDHex string

	// Epoch is the group's current epoch number. It rises by one per commit.
	Epoch int64

	// CipherSuite is the MLS suite in use.
	CipherSuite int

	// LeafCount is how many leaves the ratchet tree has, INCLUDING the blank ones that a
	// removal left behind. It is not the number of members: for that, count the occupied leaves,
	// which MemberCount does.
	LeafCount int

	// MemberCount is how many leaves actually hold a member.
	MemberCount int

	// EpochAuthenticatorHex is the epoch's authenticator, and it is here so that two members can
	// confirm they are in the same epoch.
	//
	// It is derived from the epoch secret and is NOT a key: the specification defines it for
	// exactly this comparison, and it reveals nothing that a member of the epoch does not
	// already hold. It changes every epoch, so two members that agree on it are in the same one —
	// which is the only way a client can tell "we are in step" from "we are silently apart".
	EpochAuthenticatorHex string
}

// GroupKeyPackage builds a signed KeyPackage for an identity, ready to be published so that
// another member can add it to a group.
//
// It returns hex. The KeyPackage carries public keys only, so it is safe to publish; what must
// never leave the device is the init key's PRIVATE half, which the caller does not receive here
// and which the binding keeps inside the returned state.
func GroupKeyPackage(identityJSON string) (*GroupKeyPackageResult, error) {
	identity, err := IdentityFromJSON(identityJSON)
	if err != nil {
		return nil, err
	}

	keyPackage, initPrivate, leafPrivate, err := newKeyPackage(identity)
	if err != nil {
		return nil, err
	}

	raw, err := messages.MarshalKeyPackage(keyPackage)
	if err != nil {
		return nil, fmt.Errorf("schat: encoding the KeyPackage: %w", err)
	}

	// The init key's private half is returned WITH the KeyPackage, and it is not optional: it is
	// the only thing that can open the Welcome this member will later receive. A caller that
	// published the KeyPackage and kept only it would discover the problem at the worst moment —
	// when it is being added to a group — and the symptom would be a Welcome that arrives and
	// will not open, which looks like the sender's fault.
	return &GroupKeyPackageResult{
		KeyPackageHex:     hex.EncodeToString(raw),
		InitKeyPrivateHex: hex.EncodeToString(initPrivate),
		LeafKeyPrivateHex: hex.EncodeToString(leafPrivate),
	}, nil
}

// GroupKeyPackageResult is a KeyPackage to publish together with the one secret that must be
// kept for it.
type GroupKeyPackageResult struct {
	// KeyPackageHex goes to the directory, where anyone may read it.
	KeyPackageHex string

	// InitKeyPrivateHex opens the Welcome that arrives when somebody adds this member. It must
	// go into the client's encrypted vault alongside the identity, and it must NOT be published:
	// it is a private key, and the KeyPackage it belongs to is public.
	InitKeyPrivateHex string

	// LeafKeyPrivateHex is the private half of the key the leaf publishes, and it is needed for
	// a different moment than the init key is: the init key opens the Welcome, and this one lets
	// the member follow the COMMITS that come afterwards. Section 12.4.3.1 requires the joining
	// member to set its leaf's private key to the one corresponding to the public key in the
	// tree, and that public key is this KeyPackage's.
	LeafKeyPrivateHex string
}

// GroupCreate creates a group with one member: the caller.
//
// The group is created DIRECTLY rather than by a commit — a group of one has nobody to commit
// to — so the returned state is already at epoch 0 and the caller's leaf is the root of a
// one-node tree. That member cannot generate an update path, so its first commit must be an
// Add; this is a property of the tree, not a limitation of this function.
func GroupCreate(identityJSON, groupIDHex string) (string, error) {
	identity, err := IdentityFromJSON(identityJSON)
	if err != nil {
		return "", err
	}

	groupID, err := hex.DecodeString(groupIDHex)
	if err != nil {
		return "", fmt.Errorf("schat: the group id is not hex: %w", err)
	}
	if len(groupID) == 0 {
		return "", fmt.Errorf("schat: a group needs an identifier")
	}

	suite := crypto.CipherSuite(GroupCipherSuite)

	// The creator's own leaf key pair is generated HERE and the private half is KEPT. A group
	// creator that discarded it could produce commits and follow nobody else's — the same gap
	// that GroupKeyPackage had, found the same way: by asking whether a member can keep up with a
	// group it did not itself drive.
	creatorSeed := make([]byte, 32)
	if _, err := rand.Read(creatorSeed); err != nil {
		return "", err
	}
	creatorLeafPrivate, creatorLeafPublic, err := crypto.DeriveKeyPair(creatorSeed, suite)
	if err != nil {
		return "", err
	}
	creator, err := leafNodeFor(identity, creatorLeafPublic)
	if err != nil {
		return "", err
	}

	epochSecret := make([]byte, suite.HashSize())
	if _, err := rand.Read(epochSecret); err != nil {
		return "", fmt.Errorf("schat: drawing the epoch secret: %w", err)
	}

	created, err := group.CreateGroup(group.CreateGroupSpec{
		Suite:       suite,
		GroupID:     groupID,
		Creator:     creator,
		EpochSecret: epochSecret,
	})
	if err != nil {
		return "", err
	}

	// The creator is leaf 0, so its leaf's node index is 0.
	created.Epoch.PrivateNodes = map[uint32][]byte{0: creatorLeafPrivate}

	snapshot, err := created.Epoch.Snapshot()
	if err != nil {
		return "", err
	}
	return string(snapshot), nil
}

// GroupStateSummary reads a group's state without exposing its keys.
//
// It is what the client should use for display: a snapshot holds the epoch's secrets, and a
// summary that carried them into the UI layer would spread them far beyond the vault that is
// supposed to hold them.
func GroupStateSummary(stateJSON string) (*GroupSummary, error) {
	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return nil, err
	}

	members := 0
	for i := 0; i < len(epoch.Tree); i += 2 {
		if epoch.Tree[i] != nil && epoch.Tree[i].Leaf != nil {
			members++
		}
	}

	// The ratchet tree is 2n-1 nodes for n leaves. This is the arithmetic tree.NumNodes
	// inverts, and it is written here rather than derived again because the layout is fixed.
	leaves := uint32((len(epoch.Tree) + 1) / 2)
	return &GroupSummary{
		GroupIDHex:            hex.EncodeToString(epoch.Context.GroupID),
		Epoch:                 int64(epoch.Number),
		CipherSuite:           int(epoch.Suite),
		LeafCount:             int(leaves),
		MemberCount:           members,
		EpochAuthenticatorHex: hex.EncodeToString(epoch.Secrets.EpochAuthenticator),
	}, nil
}

// leafNodeFor builds a leaf node for an identity.
//
// encryptionKey is the leaf's HPKE public key. A nil value means "generate a fresh pair and
// throw the private half away", which is what a KeyPackage needs: a KeyPackage's leaf key is
// published and the owner does not keep it, because by the time anybody uses it the leaf has
// been replaced by the commit that added them.
func leafNodeFor(identity *Identity, encryptionKey []byte) (*tree.LeafNode, error) {
	signatureKey, err := hex.DecodeString(identity.SigningPublic)
	if err != nil {
		return nil, fmt.Errorf("schat: the identity's signing key is not hex: %w", err)
	}
	if len(signatureKey) != 32 {
		return nil, fmt.Errorf("schat: the identity's signing key is %d bytes, want 32",
			len(signatureKey))
	}

	if len(encryptionKey) == 0 {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		_, public, err := crypto.DeriveKeyPair(seed, crypto.CipherSuite(GroupCipherSuite))
		if err != nil {
			return nil, err
		}
		encryptionKey = public
	}

	return &tree.LeafNode{
		EncryptionKey: encryptionKey,
		SignatureKey:  signatureKey,
		Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte(identity.SigningPublic)},
		Capabilities: tree.Capabilities{
			Versions:     []uint16{1},
			CipherSuites: []uint16{GroupCipherSuite},
		},
		Source:   tree.LeafNodeSourceKeyPackage,
		Lifetime: &tree.Lifetime{NotBefore: 0, NotAfter: 1 << 40},
	}, nil
}

// newKeyPackage builds and signs a KeyPackage, returning it and the init key's private half.
func newKeyPackage(identity *Identity) (*messages.KeyPackage, []byte, []byte, error) {
	suite := crypto.CipherSuite(GroupCipherSuite)

	// The leaf's HPKE pair is generated HERE, because the private half must be KEPT. Section
	// 12.4.3.1 requires a joining member to set its leaf's private key to "the private key
	// corresponding to the public key in the node" — that is, to the key this KeyPackage
	// publishes. An earlier version generated it inside leafNodeFor and discarded the private
	// half, justifying that in a comment; the comment was wrong, and the consequence is a member
	// that cannot follow the very commit that adds it.
	leafSeed := make([]byte, 32)
	if _, err := rand.Read(leafSeed); err != nil {
		return nil, nil, nil, err
	}
	leafPrivate, leafPublic, err := crypto.DeriveKeyPair(leafSeed, suite)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf, err := leafNodeFor(identity, leafPublic)
	if err != nil {
		return nil, nil, nil, err
	}

	// The init key is a SEPARATE key pair from the leaf's: the leaf key is what the member will
	// use inside the group, and the init key exists only to receive the Welcome. Reusing one for
	// both would mean a key published in a KeyPackage also protects the epoch's traffic.
	initSeed := make([]byte, 32)
	if _, err := rand.Read(initSeed); err != nil {
		return nil, nil, nil, err
	}
	initPrivate, initPublic, err := crypto.DeriveKeyPair(initSeed, suite)
	if err != nil {
		return nil, nil, nil, err
	}

	keyPackage := &messages.KeyPackage{
		Version:     1,
		CipherSuite: uint16(suite),
		InitKey:     initPublic,
		LeafNode:    leaf,
	}

	signatureKey, err := hex.DecodeString(identity.SigningPrivate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("schat: the identity's signing key is not hex: %w", err)
	}

	signature, err := messages.SignKeyPackage(keyPackage, signatureKey, suite)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("schat: signing the KeyPackage: %w", err)
	}
	keyPackage.Signature = signature

	return keyPackage, initPrivate, leafPrivate, nil
}
