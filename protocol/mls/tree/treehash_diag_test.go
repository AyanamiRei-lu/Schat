package tree

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
)

// TestTreeHashDiagnosis splits the tree hash failures by node kind.
//
// This test is a question, not an acceptance check, so it reports counts instead of failing.
// Its purpose is to divide a single unhelpful fact — "the hashes do not match" — into the
// only distinction that decides where to look next:
//
//   - If LEAF hashes mismatch, the fault is in LeafNodeHashInput (the leaf_index field, or
//     the width of node_type).
//   - If leaves match and PARENT hashes do not, the fault is in ParentNodeHashInput, and the
//     split between parents with a blank child and parents without localises it further,
//     because a blank child exercises the absent-optional path.
//
// Measuring this first matters: tuning the parent encoding while the leaf encoding is wrong
// is work that cannot succeed, and an earlier attempt at this diagnosis compared a "root"
// index that was actually a leaf, which produced a confident and meaningless answer.
func TestTreeHashDiagnosis(t *testing.T) {
	vectors := loadTreeVectors(t)

	var leafTotal, leafOK int
	var parentTotal, parentOKOmitted, parentOKIncluded int
	var blankChildTotal, blankChildOK int
	var blankNodeTotal, blankNodeOK int

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		tree := decodePadded(t, v)

		for x, wantHex := range v.TreeHashes {
			node := uint32(x)
			want, err := hex.DecodeString(wantHex)
			if err != nil {
				t.Fatalf("node %d: tree hash is not hex: %v", x, err)
			}

			got, err := TreeHash(tree, node, suite)
			if err != nil {
				t.Fatalf("node %d: %v", x, err)
			}

			if tree[x] == nil {
				blankNodeTotal++
				if bytes.Equal(got, want) {
					blankNodeOK++
				}
			}

			if IsLeaf(node) {
				leafTotal++
				if bytes.Equal(got, want) {
					leafOK++
				}
				continue
			}

			parentTotal++
			if bytes.Equal(got, want) {
				parentOKOmitted++
			}

			included, err := treeHashVariant(tree, node, suite, false)
			if err != nil {
				t.Fatalf("node %d: %v", x, err)
			}
			if bytes.Equal(included, want) {
				parentOKIncluded++
			}

			left, leftOK2 := Left(node)
			right, rightOK2 := Right(node)
			if leftOK2 && rightOK2 && int(right) < len(tree) &&
				(tree[left] == nil || tree[right] == nil) {
				blankChildTotal++
				if bytes.Equal(got, want) {
					blankChildOK++
				}
			}
		}
	}

	t.Logf("LEAF hashes:   %d/%d match", leafOK, leafTotal)
	t.Logf("PARENT hashes: omitted parent_hash %d/%d, included %d/%d",
		parentOKOmitted, parentTotal, parentOKIncluded, parentTotal)
	t.Logf("PARENTS whose child is blank: %d total, %d match (omitted reading)",
		blankChildTotal, blankChildOK)
	t.Logf("BLANK nodes (any kind): %d total, %d match", blankNodeTotal, blankNodeOK)

	switch {
	case leafTotal > 0 && leafOK == 0:
		t.Log("DIAGNOSIS: not one leaf hash matches, so the fault is in LeafNodeHashInput " +
			"(leaf_index or the width of node_type) — the parent encoding cannot be tuned " +
			"into correctness while this is wrong")
	case leafOK == leafTotal && parentOKOmitted+parentOKIncluded == 0:
		t.Log("DIAGNOSIS: every leaf matches and no parent does, so the fault is entirely " +
			"in ParentNodeHashInput")
	case leafOK == leafTotal && parentOKOmitted == parentTotal:
		t.Log("DIAGNOSIS: everything matches with parent_hash omitted")
	case leafOK == leafTotal && parentOKIncluded == parentTotal:
		t.Log("DIAGNOSIS: everything matches with the STORED parent_hash included")
	default:
		t.Logf("DIAGNOSIS: mixed — %d/%d leaves and at most %d/%d parents match, so more "+
			"than one thing is wrong", leafOK, leafTotal, parentOKIncluded, parentTotal)
	}
}
