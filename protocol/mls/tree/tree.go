// Package tree implements the array-based ratchet tree of RFC 9420 Appendix C.
//
// # The layout, and why it is worth stating first
//
// A tree with n leaves (n a power of two) is stored in one array of 2n-1 nodes, and the
// indexing is the part that must not be guessed:
//
//   - LEAVES ARE EVEN, INTERNAL NODES ARE ODD. Leaf i is node 2i, so the leaves of a
//     4-leaf tree are 0, 2, 4, 6 and its internal nodes are 1, 3, 5.
//   - THE ROOT IS THE INDEX n-1, not 0. For two leaves the root is node 1; for four it is
//     node 3. An implementation that assumes node 0 is the root produces a tree that is
//     internally consistent and interoperates with nothing.
//
// Both facts were read off the official tree-math vectors before this file was written,
// rather than recalled, and both are checked for every tree size the vectors cover.
//
// # What this package deliberately does not do
//
// It knows nothing about keys, hashes or encryption. Tree arithmetic is pure integer work,
// which makes it the one part of TreeKEM that can be established completely before any
// cryptography is involved — and the part that, if it is wrong, makes every later failure
// inexplicable.
package tree

import "fmt"

// ErrNotPowerOfTwo means the requested tree size is not supported.
//
// The array layout above is defined for a power-of-two number of leaves. MLS does allow
// other sizes, by leaving trailing slots blank, but that is a property of the tree's
// contents rather than of its arithmetic: the array still has the next power of two's
// shape. Anything else here would be guessing.
var ErrNotPowerOfTwo = fmt.Errorf("mls/tree: the array-based layout requires a power-of-two leaf count")

// IsPowerOfTwo reports whether n is a power of two (and not zero).
func IsPowerOfTwo(n uint32) bool { return n != 0 && n&(n-1) == 0 }

// Log2 returns the base-2 exponent of a power of two.
func Log2(n uint32) (uint32, error) {
	if !IsPowerOfTwo(n) {
		return 0, fmt.Errorf("%w: %d", ErrNotPowerOfTwo, n)
	}
	var k uint32
	for 1<<k < n {
		k++
	}
	return k, nil
}

// NumNodes is the length of the array for n leaves: 2n-1.
func NumNodes(n uint32) (uint32, error) {
	if !IsPowerOfTwo(n) {
		return 0, fmt.Errorf("%w: %d", ErrNotPowerOfTwo, n)
	}
	return 2*n - 1, nil
}

// Root is the node index of the root: n-1.
func Root(n uint32) (uint32, error) {
	if !IsPowerOfTwo(n) {
		return 0, fmt.Errorf("%w: %d", ErrNotPowerOfTwo, n)
	}
	return n - 1, nil
}

// Level is the level of a node: 0 for a leaf, up to log2(n) at the root.
//
// A node's level is the number of trailing one bits of its index, which is why the
// even/odd split works out: an even index has no trailing ones and is a leaf.
func Level(x uint32) uint32 {
	var k uint32
	for (x>>k)&1 == 1 {
		k++
	}
	return k
}

// IsLeaf reports whether a node index is a leaf.
func IsLeaf(x uint32) bool { return x%2 == 0 }

// NodeWidth is the number of leaves below a node at the given level.
func NodeWidth(level, n uint32) (uint32, error) {
	depth, err := Log2(n)
	if err != nil {
		return 0, err
	}
	if level > depth {
		return 0, fmt.Errorf("mls/tree: level %d exceeds the tree depth %d", level, depth)
	}
	return 1 << (depth - level), nil
}

// Left returns the left child of a node, or false if it has none.
func Left(x uint32) (uint32, bool) {
	level := Level(x)
	if level == 0 {
		return 0, false
	}
	return x - (1 << (level - 1)), true
}

// Right returns the right child of a node, or false if it has none.
func Right(x uint32) (uint32, bool) {
	level := Level(x)
	if level == 0 {
		return 0, false
	}
	return x + (1 << (level - 1)), true
}

// Parent returns the parent of a node, or false if it is the root.
//
// The index arithmetic is the awkward part of the layout, and it depends on the tree size:
// the parent of a leaf near the right edge is not the node one step to its right. Written
// here in the form RFC 9420 Appendix C gives, because the "obvious" version — round the
// index up to the next odd number — is right for the left half of the tree and wrong for
// the right half.
func Parent(x, n uint32) (uint32, bool) {
	root, err := Root(n)
	if err != nil {
		return 0, false
	}
	if x == root {
		return 0, false
	}

	k := Level(x)
	b := (x >> (k + 1)) & 1
	return (x | (1 << k)) ^ (b << (k + 1)), true
}

// Sibling returns the node that shares a parent with x, or false if there is none.
func Sibling(x, n uint32) (uint32, bool) {
	parent, ok := Parent(x, n)
	if !ok {
		return 0, false
	}
	if x < parent {
		return Right(parent)
	}
	return Left(parent)
}

// DirectPath returns the nodes from x's parent up to the root, in that order.
//
// This is the path a member must update when it commits: every node on it is replaced with
// fresh key material derived from its new path secret.
func DirectPath(x, n uint32) ([]uint32, error) {
	root, err := Root(n)
	if err != nil {
		return nil, err
	}

	var path []uint32
	current := x
	for current != root {
		parent, ok := Parent(current, n)
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d has no parent but is not the root", current)
		}
		path = append(path, parent)
		current = parent
	}
	return path, nil
}

// Copath returns, for each node on x's direct path, the sibling of the node below it.
//
// The path secrets travel along the direct path, and each one is encrypted to the members
// found in the resolution of the corresponding copath node — the subtree that is NOT being
// updated. Getting this off by one node means the path secret is delivered to the wrong
// subtree, which no amount of correct cryptography can repair.
func Copath(x, n uint32) ([]uint32, error) {
	path, err := DirectPath(x, n)
	if err != nil {
		return nil, err
	}

	copath := make([]uint32, 0, len(path))
	child := x
	for _, node := range path {
		sibling, ok := Sibling(child, n)
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d has no sibling", child)
		}
		copath = append(copath, sibling)
		child = node
	}
	return copath, nil
}
