package group

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/schedule"
	"github.com/schat/schat/protocol/mls/tree"
)

// Creating a group (RFC 9420 section 11).
//
// # It is not a commit
//
// The obvious-looking design — have the creator generate an Add commit for itself and process
// it — is NOT what the specification requires, and this package originally assumed it was. The
// steps are a direct initialization:
//
//   - Ratchet tree: a tree with a SINGLE NODE, a leaf holding the creator's HPKE key and
//     credential. Not a leaf plus a blank parent: for one leaf the leaf IS the root.
//   - Group ID: chosen by the creator. Random, of the hash length, so that two honest creators
//     do not collide.
//   - Epoch: 0.
//   - Epoch secret: a fresh random value of the hash length — an INPUT here, not the output of
//     the init/commit/PSK chain. That is why schedule.SecretsFromEpochSecret exists.
//   - Extensions: the creator's choice.
//
// and then the transcript:
//
//   - derive the confirmation key for the epoch;
//   - compute a confirmation tag over the EMPTY confirmed transcript hash — epoch 0's
//     confirmed hash is the zero-length octet string, not a hash of anything;
//   - compute the interim transcript hash from that confirmed hash and the tag, which is what
//     the next epoch's confirmed hash will start from.
//
// Running the commit-based route instead would mean inventing an init secret and a commit
// secret the specification never mentions for this case. The group would agree with itself and
// with nothing else, and every later epoch would inherit the difference.

// CreateGroupSpec is what a creator supplies.
type CreateGroupSpec struct {
	Suite   crypto.CipherSuite
	GroupID []byte

	// Creator is the creator's own leaf node. In a full client this comes from the creator's
	// KeyPackage; this package takes the leaf directly so that group creation does not depend
	// on the KeyPackage layer, which is not implemented yet.
	Creator *tree.LeafNode

	// EpochSecret is fresh randomness of the hash length. It is supplied rather than generated
	// here so a caller can source it from an audited generator and a test can be deterministic.
	EpochSecret []byte

	// Extensions is the already-encoded extension vector body; empty for a group with none.
	Extensions []byte
}

// CreatedGroup is a freshly created group.
type CreatedGroup struct {
	Epoch *Epoch

	// ConfirmationTag is the tag over the empty confirmed transcript hash. It is not sent
	// anywhere — nobody else exists yet to receive it — but it is folded into the interim
	// transcript hash, so a creator that skipped it would start a chain that no later member
	// could follow.
	ConfirmationTag []byte
}

// CreateGroup initializes a one-member group.
func CreateGroup(spec CreateGroupSpec) (*CreatedGroup, error) {
	if spec.Creator == nil {
		return nil, fmt.Errorf("mls/group: a group needs its creator's leaf node")
	}
	if len(spec.GroupID) == 0 {
		return nil, fmt.Errorf("mls/group: a group needs a group ID")
	}
	if len(spec.EpochSecret) != spec.Suite.HashSize() {
		return nil, fmt.Errorf("mls/group: the epoch secret is %d bytes, want %d",
			len(spec.EpochSecret), spec.Suite.HashSize())
	}

	// A tree with a single node. NumNodes(1) is 1 and Root(1) is 0 — the leaf is the root —
	// both of which the tree package verifies against the official tree-math vectors.
	ratchet := tree.Tree{
		{Type: tree.NodeTypeLeaf, Leaf: spec.Creator},
	}

	treeHash, err := treeHashOf(ratchet, spec.Suite)
	if err != nil {
		return nil, fmt.Errorf("mls/group: hashing the initial tree: %w", err)
	}

	secrets, err := schedule.SecretsFromEpochSecret(spec.EpochSecret, spec.Suite)
	if err != nil {
		return nil, err
	}

	// Epoch 0's confirmed transcript hash is the zero-length octet string, and the tag is
	// computed over it directly — there is no commit whose hash could enter the chain here.
	tag, err := messages.ConfirmationTag(secrets.ConfirmationKey, []byte{}, spec.Suite)
	if err != nil {
		return nil, err
	}
	interimInput, err := messages.InterimTranscriptHashInput(tag)
	if err != nil {
		return nil, err
	}

	context := schedule.GroupContext{
		Version:                 schedule.ProtocolVersion,
		CipherSuite:             uint16(spec.Suite),
		GroupID:                 spec.GroupID,
		Epoch:                   0,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: []byte{},
		Extensions:              spec.Extensions,
	}

	return &CreatedGroup{
		ConfirmationTag: tag,
		Epoch: &Epoch{
			Number:  0,
			Suite:   spec.Suite,
			Tree:    ratchet,
			Context: context,
			Secrets: secrets,
			// The interim hash folds in the tag, which is what lets the first real commit's
			// confirmed hash cover this group's entire history from the start.
			Transcript: messages.Transcript{
				Confirmed: []byte{},
				Interim:   spec.Suite.Hash(concat([]byte{}, interimInput)),
			},
			Proposals: messages.NewProposalCache(spec.Suite),
		},
	}, nil
}
