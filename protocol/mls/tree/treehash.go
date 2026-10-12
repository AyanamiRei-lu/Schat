package tree

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// The tree hash (RFC 9420 section 7.8).
//
// The hash of a node is the hash of a TreeHashInput, which differs by node type:
//
//	struct {
//	    NodeType node_type;
//	    select (TreeHashInput.node_type) {
//	        case leaf:   LeafNodeHashInput leaf_node;
//	        case parent: ParentNodeHashInput parent_node;
//	    };
//	} TreeHashInput;
//
//	struct {
//	    uint32 leaf_index;
//	    optional<LeafNode> leaf_node;
//	} LeafNodeHashInput;
//
//	struct {
//	    optional<ParentNode> parent_node;
//	    opaque left_hash<V>;
//	    opaque right_hash<V>;
//	} ParentNodeHashInput;
//
// Three details in there are not guessable and each one silently changes every hash:
//
//   - A leaf's hash input carries the LEAF INDEX as a uint32. Nothing in the tree's shape
//     suggests this, and without it two identical leaves at different positions would hash
//     the same.
//
//   - node_type appears ONCE, at the top of TreeHashInput. The two sub-structs do not
//     repeat it.
//
//   - A blank node is encoded as an ABSENT optional, not as a zero-length value.
//
// # The one point the specification text obtained here did not settle, and the vectors did
//
// Whether a ParentNode's own parent_hash field is included in its tree hash. It looked
// circular — a parent hash is defined in terms of the tree hash of the node above — so this
// file originally replaced the field with a zero-length value.
//
// The official vectors say otherwise: the STORED parent_hash is hashed as it appears in the
// tree, and omitting it matches nothing. The measurement that settled it was unambiguous
// once the unimplemented cipher suites were excluded: with the stored value, every parent
// hash in the covered suites matched, and with the field blanked, none did.
func TreeHash(t Tree, x uint32, suite crypto.CipherSuite) ([]byte, error) {
	return treeHashVariant(t, x, suite, false)
}

// treeHashVariant computes the tree hash. When omitParentHash is true, a parent node's own
// parent_hash is replaced with a zero-length value before hashing, breaking the circularity
// described above.
func treeHashVariant(t Tree, x uint32, suite crypto.CipherSuite, omitParentHash bool) ([]byte, error) {
	if x >= uint32(len(t)) {
		return nil, fmt.Errorf("mls/tree: node %d is outside a tree of %d nodes", x, len(t))
	}

	w := mlstls.NewWriter(256)

	if IsLeaf(x) {
		// LeafNodeHashInput{ leaf_index, optional<LeafNode> }
		w.Uint8(uint8(NodeTypeLeaf))
		w.Uint32(x / 2)

		if t[x] == nil {
			w.Optional(nil)
		} else {
			leaf := t[x].Leaf
			if leaf == nil {
				return nil, fmt.Errorf("mls/tree: node %d is a leaf but holds no leaf node", x)
			}
			w.Optional(func(w *mlstls.Writer) error { return leaf.marshal(w) })
		}
	} else {
		// ParentNodeHashInput{ optional<ParentNode>, left_hash, right_hash }
		w.Uint8(uint8(NodeTypeParent))

		if t[x] == nil {
			w.Optional(nil)
		} else {
			if t[x].Parent == nil {
				return nil, fmt.Errorf("mls/tree: node %d is a parent but holds no parent node", x)
			}
			// Copied, not mutated: clearing the field on the tree itself would corrupt the
			// tree for every later use.
			parent := *t[x].Parent
			if omitParentHash {
				parent.ParentHash = nil
			}
			p := parent
			w.Optional(func(w *mlstls.Writer) error { return p.marshal(w) })
		}

		left, leftOK := Left(x)
		right, rightOK := Right(x)
		if !leftOK || !rightOK {
			return nil, fmt.Errorf("mls/tree: node %d is a parent but has no children", x)
		}

		leftHash, err := treeHashVariant(t, left, suite, omitParentHash)
		if err != nil {
			return nil, err
		}
		rightHash, err := treeHashVariant(t, right, suite, omitParentHash)
		if err != nil {
			return nil, err
		}

		w.Opaque(leftHash)
		w.Opaque(rightHash)
	}

	if err := w.Err(); err != nil {
		return nil, err
	}
	return suite.Hash(w.Bytes()), nil
}

// TreeHashes returns the hash of every node, which is the form the official vectors publish.
func TreeHashes(t Tree, suite crypto.CipherSuite) ([][]byte, error) {
	out := make([][]byte, len(t))
	for x := range t {
		hash, err := TreeHash(t, uint32(x), suite)
		if err != nil {
			return nil, err
		}
		out[x] = hash
	}
	return out, nil
}
