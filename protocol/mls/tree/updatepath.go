package tree

import (
	"fmt"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// UpdatePath (RFC 9420 section 7.7).
//
//	struct {
//	    opaque kem_output<V>;
//	    opaque ciphertext<V>;
//	} HPKECiphertext;
//
//	struct {
//	    HPKEPublicKey encryption_key;
//	    HPKECiphertext encrypted_path_secret<V>;
//	} UpdatePathNode;
//
//	struct {
//	    LeafNode leaf_node;
//	    UpdatePathNode nodes<V>;
//	} UpdatePath;
//
// # The constraints, which matter more than the field list
//
// Three requirements in the specification are not visible in the structures above and each
// one is a silent interoperability failure if it is missed:
//
//   - The nodes are in the same order as the FILTERED direct path — the path with blank
//     nodes removed. An implementation that walks the unfiltered path produces a vector of
//     the wrong length, and the receiver cannot tell which secret belongs to which node.
//
//   - The resolution of each copath node MUST exclude every leaf added in the current
//     Commit. Those members receive the group secrets through the Welcome instead; including
//     them here would encrypt a path secret to a member who is not in the epoch it belongs
//     to.
//
//   - len(encrypted_path_secret) MUST equal the length of that filtered resolution, with the
//     i-th ciphertext addressed to the i-th node of the resolution.
//
// # Status
//
// The codec below is written from that text. The official vector set contains no UpdatePath
// vectors, so unlike the rest of this package it cannot be checked byte for byte against
// one — see docs/MLS-M3B-HANDOFF.md. What is verified here is only that a decoded path
// re-encodes to the same bytes; whether the construction matches another implementation is
// established only by an interoperability test, and must not be claimed until one exists.

// HPKECiphertext is one encrypted path secret.
//
// The two fields are opaque vectors rather than the KEM's own fixed-size types: the source
// encoding is what goes on the wire, and its length is the KEM's business.
type HPKECiphertext struct {
	KemOutput  []byte
	Ciphertext []byte
}

// UpdatePathNode is one node on the filtered direct path, with its new key and the path
// secret encrypted to every member of the corresponding copath resolution.
type UpdatePathNode struct {
	EncryptionKey       []byte
	EncryptedPathSecret []HPKECiphertext
}

// UpdatePath is a commit's new leaf plus the new key material for the path above it.
type UpdatePath struct {
	LeafNode *LeafNode
	Nodes    []UpdatePathNode
}

// ParseUpdatePath decodes an UpdatePath from a reader positioned at its start.
func ParseUpdatePath(r *mlstls.Reader) (*UpdatePath, error) {
	leaf, err := parseLeafNode(r)
	if err != nil {
		return nil, err
	}

	out := &UpdatePath{LeafNode: leaf}
	err = r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			var node UpdatePathNode
			if node.EncryptionKey, err = r.Opaque(); err != nil {
				return err
			}
			if err := r.Vector(func(r *mlstls.Reader) error {
				for !r.Empty() {
					var ct HPKECiphertext
					var err error
					if ct.KemOutput, err = r.Opaque(); err != nil {
						return err
					}
					if ct.Ciphertext, err = r.Opaque(); err != nil {
						return err
					}
					node.EncryptedPathSecret = append(node.EncryptedPathSecret, ct)
				}
				return nil
			}); err != nil {
				return err
			}
			out.Nodes = append(out.Nodes, node)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// marshal encodes an UpdatePath.
func (u *UpdatePath) marshal(w *mlstls.Writer) error {
	if u.LeafNode == nil {
		return fmt.Errorf("mls/tree: an update path must carry a leaf node")
	}
	if err := u.LeafNode.marshal(w); err != nil {
		return err
	}

	w.Vector(func(w *mlstls.Writer) error {
		for _, node := range u.Nodes {
			w.Opaque(node.EncryptionKey)
			w.Vector(func(w *mlstls.Writer) error {
				for _, ct := range node.EncryptedPathSecret {
					w.Opaque(ct.KemOutput)
					w.Opaque(ct.Ciphertext)
				}
				return nil
			})
		}
		return nil
	})
	return nil
}

// MarshalUpdatePath encodes an UpdatePath, including any enclosing length prefix the caller
// applies.
func MarshalUpdatePath(u *UpdatePath) ([]byte, error) {
	w := mlstls.NewWriter(512)
	if err := u.marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// CheckShape enforces the constraints that the structures do not express.
//
// It is separate from the codec on purpose: a path can be perfectly well-formed as bytes and
// still be invalid as an UpdatePath, and a decoder that rejected such a path outright would
// make a mis-encoding indistinguishable from a corrupt one during diagnosis.
//
// resolutionSizes gives, for each node of the path, the expected number of ciphertexts —
// that is, the length of the corresponding copath resolution after new leaves are excluded.
func (u *UpdatePath) CheckShape(pathLength int, resolutionSizes []int) error {
	if len(u.Nodes) != pathLength {
		return fmt.Errorf("mls/tree: the update path has %d nodes but the filtered direct path has %d",
			len(u.Nodes), pathLength)
	}
	if len(resolutionSizes) != len(u.Nodes) {
		return fmt.Errorf("mls/tree: %d resolution sizes for %d path nodes",
			len(resolutionSizes), len(u.Nodes))
	}

	for i, node := range u.Nodes {
		if len(node.EncryptedPathSecret) != resolutionSizes[i] {
			return fmt.Errorf("mls/tree: path node %d carries %d encrypted secrets but its copath "+
				"resolution has %d members", i, len(node.EncryptedPathSecret), resolutionSizes[i])
		}
	}
	return nil
}

// FilteredDirectPath returns the nodes from x's parent up to the root with blank nodes
// removed, which is the order and the length an UpdatePath must follow.
func FilteredDirectPath(t Tree, x uint32) ([]uint32, error) {
	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return nil, err
	}

	path, err := DirectPath(x, leaves)
	if err != nil {
		return nil, err
	}

	out := make([]uint32, 0, len(path))
	for _, node := range path {
		if int(node) < len(t) && t[node] != nil {
			out = append(out, node)
		}
	}
	return out, nil
}
