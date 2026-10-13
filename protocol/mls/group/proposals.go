package group

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Applying a commit's proposals to a working tree.
//
// # Why this is one function and not two
//
// The sender and the receiver must build the SAME tree from the same commit. They were written
// separately, and they drifted: the receiver learned to place added leaves and to extend the
// tree, while the sender kept a loop that handled only removals. A commit adding a member then
// produced two different trees — the sender's without the new member, the receiver's with it —
// and the disagreement surfaced as a confirmation tag that would not verify, pointing at the
// tag rather than at the tree.
//
// This is the second time this project has been bitten by writing the same rule twice: the
// exclusion set was computed by the sender and not by the receiver, and now the proposal
// effects were applied by the receiver and not by the sender. The rule is therefore kept here,
// once, and both sides call it.
//
// # The order inside is not arbitrary
//
// Removals are applied before additions. A commit can remove one member and add another in the
// same breath, and the two must land in the tree the specification describes: the removed
// member's leaf is a hole, and a new member takes a free slot at the RIGHT EDGE — which may be
// that very hole. Applying additions first would extend the tree unnecessarily and place the
// new member a level deeper than it belongs, changing the tree hash.
//
// # What it returns
//
// The tree, and the leaf indices it added. The caller needs those indices because a new member
// must be kept OUT of the update path's recipients: it learns the epoch through its Welcome, so
// a path secret sent to it would hand key material to somebody who is not in the epoch it
// belongs to.

// applyProposalEffects returns the tree a commit's proposals produce.
//
// It does not touch the update path: the path is applied afterwards, against this tree, by the
// caller. groupVersion and groupCipherSuite are the values from the epoch's GroupContext, and
// are used to reject a KeyPackage that describes a different group.
func applyProposalEffects(
	current tree.Tree,
	proposals []*messages.ProposalOrRef,
	groupVersion, groupCipherSuite uint16,
	suite crypto.CipherSuite,
) (tree.Tree, []uint32, error) {
	// A copy, so that a commit which fails validation leaves the epoch it was validated
	// against untouched. Without this the caller's tree is mutated as proposals are applied,
	// and a rejected commit would have already changed the group's state.
	working := make(tree.Tree, len(current))
	copy(working, current)
	current = working

	// Collected first, applied in the order the specification requires rather than the order
	// the proposals happen to appear in.
	var removeLeaves []uint32
	var addLeaves []*tree.LeafNode

	for _, ref := range proposals {
		if ref == nil || ref.Proposal == nil {
			return nil, nil, fmt.Errorf("mls/group: the commit cites a proposal by reference; " +
				"resolve it from the cache and supply it inline before processing")
		}

		switch ref.Proposal.Type {
		case messages.ProposalTypeRemove:
			if ref.Proposal.Remove == nil {
				return nil, nil, fmt.Errorf("mls/group: a Remove proposal with no leaf index")
			}
			removeLeaves = append(removeLeaves, ref.Proposal.Remove.Removed)

		case messages.ProposalTypeAdd:
			if ref.Proposal.Add == nil || ref.Proposal.Add.KeyPackage == nil {
				return nil, nil, fmt.Errorf("mls/group: an Add proposal with no KeyPackage")
			}
			keyPackage := ref.Proposal.Add.KeyPackage

			// The package must describe THIS group. One for another version or another
			// ciphersuite would put a member in the tree whose keys nothing here can use, and
			// the mismatch would surface much later as a member that cannot read anything.
			if err := messages.VerifyKeyPackage(keyPackage, groupVersion, groupCipherSuite, suite); err != nil {
				return nil, nil, err
			}
			addLeaves = append(addLeaves, keyPackage.LeafNode)

		case messages.ProposalTypeUpdate:
			// An Update's effect is the sender's new leaf node, which travels in the path
			// rather than in the proposal.

		default:
			return nil, nil, fmt.Errorf("mls/group: proposal type %d cannot be applied by this "+
				"implementation", ref.Proposal.Type)
		}
	}

	for _, leaf := range removeLeaves {
		node := 2 * leaf
		if int(node) >= len(current) {
			return nil, nil, fmt.Errorf("mls/group: Remove refers to leaf %d, outside a tree of "+
				"%d nodes", leaf, len(current))
		}
		if current[node] == nil {
			return nil, nil, fmt.Errorf("mls/group: Remove refers to leaf %d, which is already blank", leaf)
		}
		current[node] = nil
	}

	var added []uint32
	for _, leafNode := range addLeaves {
		// The tree grows only when there is no room: a blank leaf slot is a place to put a new
		// member, and extending a tree that has one would place that member a level deeper than
		// it belongs and change the tree hash.
		needsExtension, err := tree.NeedsExtension(current)
		if err != nil {
			return nil, nil, err
		}
		if needsExtension {
			current, err = tree.Extend(current)
			if err != nil {
				return nil, nil, fmt.Errorf("mls/group: extending the tree for an Add: %w", err)
			}
		}

		slot, ok, err := tree.FirstFreeLeaf(current)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, fmt.Errorf("mls/group: no free leaf slot for an Add even after extending")
		}
		current[2*slot] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: leafNode}
		added = append(added, slot)
	}

	return current, added, nil
}
