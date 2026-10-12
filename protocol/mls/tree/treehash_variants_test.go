package tree

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// TestTreeHashLeafVariants is the second round of diagnosis.
//
// The first round established that 57% of LEAF hashes were already wrong, which means the
// fault is upstream of the parent encoding and no amount of parent tuning can fix it. This
// test answers the next question in one run instead of several: WHICH leaf encoding is right.
//
// Four candidate shapes are tried against the published leaf hashes:
//
//	index+u8      node_type(u8) ‖ leaf_index(u32) ‖ optional<LeafNode>  — the reading of §7.8 used so far
//	no-index+u8   node_type(u8) ‖ optional<LeafNode>
//	index+u16     node_type(u16) ‖ leaf_index(u32) ‖ optional<LeafNode>
//	optional-first optional<LeafNode> ‖ node_type(u8) ‖ leaf_index(u32)
//
// Counts are reported separately for blank and non-blank leaves, because the two take
// different paths — a blank leaf has no optional value — so a variant can be right for one
// and wrong for the other.
//
// Nothing here asserts; it is a question. The assertion lives in the acceptance test, which
// is not allowed to pass until the right shape is in the implementation.
func TestTreeHashLeafVariants(t *testing.T) {
	vectors := loadTreeVectors(t)

	type bucket struct{ ok, total int }
	names := []string{"index+u8", "no-index+u8", "index+u16", "optional-first"}
	results := map[string]map[string]*bucket{}

	for _, name := range names {
		results[name] = map[string]*bucket{"blank": {}, "present": {}}
	}

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		tree := decodePadded(t, v)

		for x, wantHex := range v.TreeHashes {
			node := uint32(x)
			if !IsLeaf(node) {
				continue
			}
			want, err := hex.DecodeString(wantHex)
			if err != nil {
				t.Fatalf("node %d: %v", x, err)
			}

			kind := "present"
			if tree[x] == nil {
				kind = "blank"
			}

			for _, name := range names {
				got, err := leafVariant(tree, node, suite, name)
				if err != nil {
					t.Fatalf("node %d (%s): %v", x, name, err)
				}
				results[name][kind].total++
				if bytes.Equal(got, want) {
					results[name][kind].ok++
				}
			}
		}
	}

	for _, name := range names {
		t.Logf("%-16s blank %4d/%-4d   present %4d/%-4d",
			name,
			results[name]["blank"].ok, results[name]["blank"].total,
			results[name]["present"].ok, results[name]["present"].total)
	}

	for _, name := range names {
		blank, present := results[name]["blank"], results[name]["present"]
		if blank.total > 0 && present.total > 0 && blank.ok == blank.total && present.ok == present.total {
			t.Logf("ANSWER: the leaf hash input is %q — all %d leaf hashes match",
				name, blank.total+present.total)
			return
		}
	}
	t.Log("ANSWER: no candidate matches every leaf; see the per-bucket counts above")
}

// leafVariant encodes one candidate leaf hash input and hashes it.
func leafVariant(t Tree, x uint32, suite crypto.CipherSuite, variant string) ([]byte, error) {
	w := mlstls.NewWriter(256)

	writeType := func() {
		if variant == "index+u16" {
			w.Uint16(uint16(NodeTypeLeaf))
		} else {
			w.Uint8(uint8(NodeTypeLeaf))
		}
	}
	writeIndex := func() { w.Uint32(x / 2) }
	writeBody := func() error {
		if t[x] == nil {
			w.Optional(nil)
			return nil
		}
		if t[x].Leaf == nil {
			return fmt.Errorf("mls/tree: node %d is a leaf but holds no leaf node", x)
		}
		leaf := t[x].Leaf
		w.Optional(func(w *mlstls.Writer) error { return leaf.marshal(w) })
		return nil
	}

	switch variant {
	case "index+u8":
		writeType()
		writeIndex()
		if err := writeBody(); err != nil {
			return nil, err
		}
	case "no-index+u8":
		writeType()
		if err := writeBody(); err != nil {
			return nil, err
		}
	case "index+u16":
		writeType()
		writeIndex()
		if err := writeBody(); err != nil {
			return nil, err
		}
	case "optional-first":
		if err := writeBody(); err != nil {
			return nil, err
		}
		writeType()
		writeIndex()
	default:
		return nil, fmt.Errorf("mls/tree: unknown leaf hash variant %q", variant)
	}

	if err := w.Err(); err != nil {
		return nil, err
	}
	return suite.Hash(w.Bytes()), nil
}
