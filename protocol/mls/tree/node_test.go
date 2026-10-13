package tree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

type treeValidationVector struct {
	CipherSuite uint16     `json:"cipher_suite"`
	Tree        string     `json:"tree"`
	GroupID     string     `json:"group_id"`
	TreeHashes  []string   `json:"tree_hashes"`
	Resolutions [][]uint32 `json:"resolutions"`
}

// TestTreeRoundTripAgainstOfficialVectors is the acceptance criterion for the node codec.
//
// Decoding each official tree and re-encoding it must reproduce the original bytes EXACTLY.
// Nothing weaker would do: any difference at all produces a different tree hash, and
// therefore a different epoch secret, from identical group contents — a failure that looks
// like a decryption problem and is not one.
//
// The node count is cross-checked against the vector's own tree_hashes, which is evidence
// that does not depend on this package's understanding of the layout being right.
func TestTreeRoundTripAgainstOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "tree-validation.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []treeValidationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("tree-validation.json is not valid JSON: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("the vector file is empty")
	}

	totalNodes, totalLeaves := 0, 0
	unsupported := 0

	for i, v := range vectors {
		raw, err := hex.DecodeString(v.Tree)
		if err != nil {
			t.Fatalf("vector %d: tree is not hex: %v", i, err)
		}

		tree, err := ParseTree(mlstls.NewReader(raw))
		if err != nil {
			t.Fatalf("vector %d (%d bytes): parsing the tree: %v", i, len(raw), err)
		}

		encoded, err := MarshalTree(tree)
		if err != nil {
			t.Fatalf("vector %d: re-encoding the tree: %v", i, err)
		}

		if !bytes.Equal(encoded, raw) {
			t.Errorf("vector %d: the tree did not survive a round trip\n%s",
				i, describeDifference(raw, encoded))
			continue
		}

		// The vector's tree_hashes cover the FULL array layout (2n-1 nodes), while the
		// encoding omits trailing blank nodes. An earlier version of this check compared
		// the two directly and so reported a mismatch on every tree with a blank right
		// edge — a bug in the check, not in the codec, and one that obscured the fact that
		// the round trip above was already exact.
		//
		// This matters well beyond the test: resolution and the tree hash are computed over
		// the PADDED tree, never over the length of the encoding.
		hashes := len(v.TreeHashes)
		if hashes == 0 || hashes%2 == 0 {
			t.Errorf("vector %d: %d tree hashes is not a 2n-1 layout", i, hashes)
			continue
		}
		layoutLeaves := (hashes + 1) / 2
		if !IsPowerOfTwo(uint32(layoutLeaves)) {
			t.Errorf("vector %d: %d tree hashes implies %d leaves, not a power of two",
				i, hashes, layoutLeaves)
			continue
		}
		if len(tree) > hashes {
			t.Errorf("vector %d: the encoding holds %d nodes, more than the layout's %d",
				i, len(tree), hashes)
			continue
		}

		leaves := 0
		for idx, node := range tree {
			if node == nil {
				continue
			}
			if node.Type == NodeTypeLeaf {
				if idx%2 != 0 {
					t.Errorf("vector %d: node %d is a leaf but leaves must be at even indices", i, idx)
				}
				leaves++
			}
			unsupported += 0
		}
		totalNodes += len(tree)
		totalLeaves += leaves
	}

	t.Logf("round-tripped %d official trees exactly (%d nodes, %d leaves)",
		len(vectors)-unsupported, totalNodes, totalLeaves)
}

// describeDifference reports where two encodings first differ, in bytes.
//
// A bare "the bytes differ" is useless on a 421-byte structure: the whole difficulty is
// working out which field moved. Reporting the offset turns that into a one-line answer.
func describeDifference(want, got []byte) string {
	limit := len(want)
	if len(got) < limit {
		limit = len(got)
	}

	for i := 0; i < limit; i++ {
		if want[i] != got[i] {
			return fmt.Sprintf("first difference at byte %d (0x%02x): wrote 0x%02x, expected 0x%02x\n"+
				"  wrote:    %x\n  expected: %x",
				i, i, got[i], want[i], got[max(0, i-8):min(len(got), i+8)], want[max(0, i-8):min(len(want), i+8)])
		}
	}
	return fmt.Sprintf("the encodings share a %d-byte prefix but differ in length: wrote %d bytes, expected %d",
		limit, len(got), len(want))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
