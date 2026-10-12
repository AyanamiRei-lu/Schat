package tree

import "fmt"

// This file is the first half of M3b part two: the tree as an algorithm operates on it,
// rather than as it is serialised.
//
// # The padding rule, learned from the vectors
//
// A decoded tree is usually SHORTER than its array layout, because the wire encoding omits
// trailing blank nodes. Every algorithm below therefore needs the full 2n-1 width, and an
// implementation that uses len(tree) instead computes the wrong answer on exactly those
// trees whose right edge is blank — which is most of them after a removal.
//
// An earlier version of the round-trip test made this mistake in reverse: it asserted that
// the encoded node count equals the layout's, and so reported failures on 60 of the 98
// official trees while the codec itself was correct.

// LayoutSize is the number of nodes in the full array layout for n leaves: 2n-1.
func LayoutSize(n uint32) (uint32, error) {
	// Reuses NumNodes so that there is a single definition of the layout width.
	return NumNodes(n)
}

// LeavesForLayout returns the leaf count implied by a layout width, or an error if the
// width is not of the form 2n-1 for a power-of-two n.
func LeavesForLayout(layout uint32) (uint32, error) {
	if layout == 0 || layout%2 == 0 {
		return 0, fmt.Errorf("mls/tree: %d is not a 2n-1 layout width", layout)
	}
	n := (layout + 1) / 2
	if !IsPowerOfTwo(n) {
		return 0, fmt.Errorf("mls/tree: layout width %d implies %d leaves, not a power of two", layout, n)
	}
	return n, nil
}

// Padded returns the tree widened to the full layout, filling the tail with blank nodes.
//
// It returns the input unchanged when it is already wide enough, so callers can apply it
// unconditionally without copying on the common path.
func Padded(t Tree, layout uint32) (Tree, error) {
	if _, err := LeavesForLayout(layout); err != nil {
		return nil, err
	}
	if uint32(len(t)) >= layout {
		return t, nil
	}
	out := make(Tree, layout)
	copy(out, t)
	return out, nil
}

// Resolution returns the resolution of node x (RFC 9420 section 4.2), in tree order.
//
// The resolution is the shortest list of nodes that covers x's subtree:
//
//   - if x holds a value, the list is just [x];
//   - if x is a blank leaf, the list is empty;
//   - if x is a blank parent, it is the concatenation of its children's resolutions.
//
// This is what an UpdatePath encrypts each path secret to, so an off-by-one node here hands
// the secret to the wrong subtree. The failure then appears as a member who cannot decrypt
// anything, with nothing to suggest the cause was an index.
func Resolution(t Tree, x uint32) ([]uint32, error) {
	if x >= uint32(len(t)) {
		return nil, fmt.Errorf("mls/tree: node %d is outside a tree of %d nodes", x, len(t))
	}
	out := make([]uint32, 0, 4)
	if err := resolutionInto(t, x, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func resolutionInto(t Tree, x uint32, out *[]uint32) error {
	if t[x] != nil {
		*out = append(*out, x)

		// "The resolution of a non-blank node comprises the node itself, followed by its
		// list of unmerged leaves, if any." (RFC 9420 section 4.2)
		//
		// The field holds LEAF indices while a resolution is a list of NODE indices, so
		// each one is doubled. Omitting this clause was the first version's entire bug: it
		// left 22 of 3178 resolutions wrong, and every one of them was a node above an
		// unmerged leaf — precisely the node an UpdatePath encrypts a path secret to, so
		// the secret would have gone to a subtree that could never open it.
		if t[x].Parent != nil {
			for _, leafIndex := range t[x].Parent.UnmergedLeaves {
				*out = append(*out, 2*leafIndex)
			}
		}
		return nil
	}
	if IsLeaf(x) {
		return nil
	}

	left, ok := Left(x)
	if !ok {
		return fmt.Errorf("mls/tree: node %d is a parent but has no left child", x)
	}
	right, ok := Right(x)
	if !ok {
		return fmt.Errorf("mls/tree: node %d is a parent but has no right child", x)
	}
	if int(right) >= len(t) {
		return fmt.Errorf("mls/tree: node %d has a right child %d outside a tree of %d nodes",
			x, right, len(t))
	}

	if err := resolutionInto(t, left, out); err != nil {
		return err
	}
	return resolutionInto(t, right, out)
}

// ResolutionOfAll returns the resolution of every node, which is the form the official
// vectors publish and therefore the form the acceptance test compares against.
func ResolutionOfAll(t Tree) ([][]uint32, error) {
	out := make([][]uint32, len(t))
	for x := range t {
		resolution, err := Resolution(t, uint32(x))
		if err != nil {
			return nil, err
		}
		out[x] = resolution
	}
	return out, nil
}
