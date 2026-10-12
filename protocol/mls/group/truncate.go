package group

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/tree"
)

// Truncating after a removal (RFC 9420 section 7.7).
//
// # What this exists for, and why it is not tidiness
//
// Removing a member blanks its leaf. If that leaf was the last live node of the root's right
// subtree, the tree now has an entirely blank half, and the specification says that half is
// discarded: the root and the right subtree go, and the left child becomes the new root.
//
// Whether that happens decides the TREE HASH, and the tree hash is an input to the key
// schedule. So two implementations that differ here derive different epoch secrets from
// identical membership. The failure is invisible locally — both sides of a test run the same
// code and agree — and shows up only as a confirmation tag that will not verify against
// somebody else's client, pointing at the tag rather than at the tree.
//
// This package kept the tree's shape after a removal and a test asserted that as if it were a
// property. It is not a property; it is a disagreement.
//
// # The detail that is easy to miss
//
// Truncation makes the old left child the new ROOT, and a root's parent hash is the
// zero-length string — it has nothing above it to hash. The node kept the parent hash it had
// while it was an ordinary internal node, which described the root that has just been
// discarded. Leaving it in place produces a tree whose root claims a parent that no longer
// exists, and the parent hash chain of every member below it is then checked against a value
// that cannot be right.
//
// # Where it must be called
//
// Both paths that produce a tree from a commit have to apply this: the sender's, in
// CreateCommit, and the receiver's, in ProcessCommit's applyProposalsAndPath. Calling it in
// only one of them is worse than calling it in neither, because the two sides would then
// disagree with each other as well as with everybody else.

// TruncateIfTheRightSubtreeIsBlank applies the specification's rule and returns the tree that
// should result from a commit.
//
// It returns the input unchanged when the right subtree still holds a live member.
func TruncateIfTheRightSubtreeIsBlank(t tree.Tree) (tree.Tree, error) {
	blank, err := tree.RightSubtreeIsBlank(t)
	if err != nil {
		return nil, err
	}
	if !blank {
		return t, nil
	}

	truncated, err := tree.Truncate(t)
	if err != nil {
		return nil, err
	}

	// The new root has nothing above it, so its parent hash is the empty string. Clearing it
	// is not cosmetic: the value it carries describes the node that was just discarded.
	leaves, err := tree.LeavesForLayout(uint32(len(truncated)))
	if err != nil {
		return nil, err
	}
	root, err := tree.Root(leaves)
	if err != nil {
		return nil, err
	}

	switch {
	case truncated[root] == nil:
		// A blank root is possible after truncation only if the whole tree is blank, which no
		// member can be in: refusing is better than returning a tree with no root to hash.
		return nil, fmt.Errorf("mls/group: truncation produced a blank root, so there is nothing " +
			"left to hash")
	case truncated[root].Parent != nil:
		parent := *truncated[root].Parent
		parent.ParentHash = []byte{}
		truncated[root] = &tree.Node{Type: tree.NodeTypeParent, Parent: &parent}
	}

	return truncated, nil
}
