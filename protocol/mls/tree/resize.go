package tree

import "fmt"

// Extending and truncating the tree (RFC 9420 section 7.7).
//
//	Leaves are always added and removed at the RIGHT EDGE of the tree. When the size of the
//	tree needs to be increased, a new blank root node is added, whose left subtree is the
//	existing tree and right subtree is a new all-blank subtree.
//
//	When the right subtree of the tree no longer has any non-blank nodes, it can be safely
//	removed. The root of the tree and the right subtree are discarded... The left child of the
//	root becomes the new root node, and the left subtree becomes the new tree.
//
// # Why this is not an optimisation
//
// A removal blanks a leaf, and if that leaf was the last live node of the root's right
// subtree, the tree has a whole blank half. Whether that half is kept or discarded decides the
// TREE HASH, and the tree hash is an input to the key schedule. Two implementations that
// differ here compute different epoch secrets from identical membership — and the only
// symptom is a confirmation tag that will not verify, which points at the tag rather than at
// the tree.
//
// This package's removal handling kept the tree's shape, and a test asserted that as if it
// were a property. It is not: an implementation that truncates agrees with every other
// implementation and disagrees with the one that does not.
//
// # The array layout makes both operations exact
//
// For a full tree of n leaves the layout has 2n-1 nodes and the root sits at n-1. Its left
// subtree is therefore exactly the FIRST HALF of the array and its right subtree the second
// half, so truncating is a slice and extending is a concatenation. That is a property of the
// layout rather than a coincidence, and the tests below check it at several sizes.

// RightSubtreeIsBlank reports whether every node in the root's right subtree is blank.
//
// This is the condition the specification gives for truncating. A tree whose right subtree
// still holds a live member must not be truncated: that member's leaf would be discarded while
// it is still in the group.
func RightSubtreeIsBlank(t Tree) (bool, error) {
	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return false, err
	}
	if leaves < 2 {
		// A one-leaf tree has no right subtree to discard, and truncating it would leave
		// nothing at all.
		return false, nil
	}

	for _, node := range t[leaves:] {
		if node != nil {
			return false, nil
		}
	}
	return true, nil
}

// Truncate discards the root and the right subtree, returning the left subtree as the new
// tree.
//
// It refuses when the right subtree still holds a live node rather than silently dropping it:
// a caller that truncated a tree with a member in it would remove that member from the group
// without any proposal saying so, and the tree hash would still be self-consistent.
func Truncate(t Tree) (Tree, error) {
	blank, err := RightSubtreeIsBlank(t)
	if err != nil {
		return nil, err
	}
	if !blank {
		return nil, fmt.Errorf("mls/tree: the right subtree still holds a live node, so the tree " +
			"must not be truncated")
	}

	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return nil, err
	}
	if leaves < 2 {
		return nil, fmt.Errorf("mls/tree: a one-leaf tree cannot be truncated")
	}

	// The left subtree of the root is the first half of the array: 2*(leaves/2)-1 nodes.
	half := int(leaves/2)*2 - 1

	out := make(Tree, half)
	copy(out, t[:half])
	return out, nil
}

// Extend adds a level, keeping the existing tree as the left subtree and making the right
// subtree all blank.
//
// The new tree has twice the leaves. Every index below the new root keeps its meaning, which
// is why the operation is a padding rather than a re-layout: the old array becomes the left
// half of the new one, and the right half is blank.
func Extend(t Tree) (Tree, error) {
	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return nil, err
	}

	newLeaves := leaves * 2
	newLen, err := NumNodes(newLeaves)
	if err != nil {
		return nil, err
	}

	out := make(Tree, newLen)
	copy(out, t)
	return out, nil
}

// NeedsExtension reports whether the tree is full, so that adding a leaf requires a new level.
//
// "Full" here means every leaf slot holds a node. A tree with blank leaves has room, and the
// specification places new leaves at the RIGHT EDGE — so a tree that is not full is extended
// only when no blank slot remains.
func NeedsExtension(t Tree) (bool, error) {
	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return false, err
	}
	for i := uint32(0); i < leaves; i++ {
		if t[2*i] == nil {
			return false, nil
		}
	}
	return true, nil
}

// FirstFreeLeaf returns the rightmost blank leaf slot, which is where a new member goes.
//
// It returns false when every slot is taken, in which case the caller must Extend first. The
// scan goes from the right because the specification adds leaves at the right edge; taking the
// leftmost slot instead would put a new member in a position another member's path already
// covers, and the two would disagree about the tree that results.
func FirstFreeLeaf(t Tree) (uint32, bool, error) {
	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return 0, false, err
	}
	for i := leaves; i > 0; i-- {
		if t[2*(i-1)] == nil {
			return i - 1, true, nil
		}
	}
	return 0, false, nil
}
