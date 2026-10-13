package tree

import (
	"bytes"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// Parent hashes (RFC 9420 section 7.9).
//
// A parent hash binds a node's key to everything above it, which is what lets a member that
// has been away verify that a new tree state is an extension of the one it last saw. The
// input is:
//
//	struct {
//	    HPKEPublicKey encryption_key;
//	    opaque parent_hash<V>;
//	    opaque original_sibling_tree_hash<V>;
//	} ParentHashInput;
//
// and the three fields are, in the order they are written:
//
//   - the node's OWN public key;
//   - the node's own stored parent_hash, which is the hash of the next node up the path —
//     and is a zero-length value when the node is the root, which is what terminates the
//     chain;
//   - the tree hash, taken from the ORIGINAL tree (the state before the update being
//     verified) of the node's copath child: the sibling subtree that the update did not
//     touch.
//
// The value is stored in the node BELOW, so a path reads as a chain: each node's
// parent_hash covers its parent's key and the sibling subtree it left behind.
//
// # Status
//
// This is written from the specification text but has NOT yet been checked against the
// official treekem vectors, so treat it as unverified. In particular the "original tree"
// hashes must come from the caller: an update cannot be verified against the tree it
// produced, which is the whole point of the field.

// ParentHash computes the parent hash of node p.
//
// originalSiblingTreeHash is the tree hash of p's copath child in the tree as it stood
// BEFORE the update, not in the tree being verified.
func ParentHash(t Tree, p uint32, originalSiblingTreeHash []byte, suite crypto.CipherSuite) ([]byte, error) {
	if p >= uint32(len(t)) {
		return nil, fmt.Errorf("mls/tree: node %d is outside a tree of %d nodes", p, len(t))
	}
	if t[p] == nil || t[p].Parent == nil {
		return nil, fmt.Errorf("mls/tree: node %d is not a parent node", p)
	}

	w := mlstls.NewWriter(128)
	w.Opaque(t[p].Parent.EncryptionKey)
	w.Opaque(t[p].Parent.ParentHash)
	w.Opaque(originalSiblingTreeHash)
	if err := w.Err(); err != nil {
		return nil, err
	}
	return suite.Hash(w.Bytes()), nil
}

// VerifyParentHashes recomputes every parent hash in the tree and reports the first
// mismatch.
//
// originalHashes holds the tree hash of every node in the tree as it stood before the
// update, indexed by node. The walk is over each leaf's direct path: the node below a
// parent p on that path is the one whose stored parent_hash must equal ParentHash(p), and
// p's copath child is that node's sibling.
func VerifyParentHashes(t Tree, originalHashes [][]byte, suite crypto.CipherSuite) error {
	if len(originalHashes) != len(t) {
		return fmt.Errorf("mls/tree: %d original tree hashes for %d nodes",
			len(originalHashes), len(t))
	}

	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return err
	}
	root, err := Root(leaves)
	if err != nil {
		return err
	}

	checked := 0
	for leaf := uint32(0); leaf < leaves; leaf++ {
		x := 2 * leaf
		if int(x) >= len(t) {
			break
		}

		child := x
		for child != root {
			parent, ok := Parent(child, leaves)
			if !ok {
				break
			}
			if t[parent] != nil && t[parent].Parent != nil {
				sibling, ok := Sibling(child, leaves)
				if !ok {
					return fmt.Errorf("mls/tree: node %d has no sibling", child)
				}
				if int(sibling) >= len(originalHashes) {
					return fmt.Errorf("mls/tree: sibling %d has no original tree hash", sibling)
				}
				if t[child] != nil && t[child].Parent != nil {
					want := t[child].Parent.ParentHash
					got, err := ParentHash(t, parent, originalHashes[sibling], suite)
					if err != nil {
						return err
					}
					if !bytes.Equal(got, want) {
						return fmt.Errorf("mls/tree: parent hash stored at node %d =\n  %x\nbut node %d's parent hash computes to\n  %x",
							child, want, parent, got)
					}
					checked++
				}
			}
			child = parent
		}
	}

	if checked == 0 {
		return fmt.Errorf("mls/tree: no parent hash was checked; the tree may be entirely blank")
	}
	return nil
}
