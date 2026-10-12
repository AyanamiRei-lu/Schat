package tree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

func loadTreeVectors(t *testing.T) []treeValidationVector {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "vectors", "tree-validation.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []treeValidationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("tree-validation.json is not valid JSON: %v", err)
	}
	return vectors
}

// decodePadded decodes a vector's tree and widens it to the full layout.
//
// The widening is the point: the encoding omits trailing blank nodes, so every algorithm
// must run on the full width or it computes a different answer on exactly the trees whose
// right edge is blank.
func decodePadded(t *testing.T, v treeValidationVector) Tree {
	t.Helper()

	raw, err := hex.DecodeString(v.Tree)
	if err != nil {
		t.Fatalf("tree is not hex: %v", err)
	}
	decoded, err := ParseTree(mlstls.NewReader(raw))
	if err != nil {
		t.Fatalf("parsing the tree: %v", err)
	}
	padded, err := Padded(decoded, uint32(len(v.TreeHashes)))
	if err != nil {
		t.Fatalf("padding the tree: %v", err)
	}
	return padded
}

// TestResolutionsAgainstOfficialVectors checks the resolution of EVERY node, not just the
// leaves, because that is what the vector publishes and because the copath resolutions are
// the ones an UpdatePath encrypts to.
func TestResolutionsAgainstOfficialVectors(t *testing.T) {
	vectors := loadTreeVectors(t)

	checked := 0
	for i, v := range vectors {
		tree := decodePadded(t, v)

		if len(tree) != len(v.Resolutions) {
			t.Fatalf("vector %d: tree has %d nodes but the vector lists %d resolutions",
				i, len(tree), len(v.Resolutions))
		}

		got, err := ResolutionOfAll(tree)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}

		for x := range got {
			if !equalUint32s(got[x], v.Resolutions[x]) {
				t.Errorf("vector %d: resolution of node %d = %v, want %v",
					i, x, got[x], v.Resolutions[x])
			}
			checked++
		}
	}

	t.Logf("verified %d node resolutions across %d trees", checked, len(vectors))
}

// TestTreeHashesAgainstOfficialVectors is the acceptance criterion for the tree hash.
//
// It also settles the one question the specification text available here left open — whether
// a parent's own parent_hash is included when hashing it — by REPORTING which of the two
// readings reproduces the published hashes, so that a mismatch is diagnosed in the same run
// rather than in another round of guesswork.
func TestTreeHashesAgainstOfficialVectors(t *testing.T) {
	vectors := loadTreeVectors(t)

	checked := 0
	unsupported := 0
	for i, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			// The suite's hash is not implemented, so comparing digests is meaningless:
			// hashing a SHA-384 or SHA-512 suite with SHA-256 produces bytes that cannot
			// match for any reason to do with the tree hash input.
			//
			// Not skipping these caused a long search for a bug that did not exist. The
			// give-away was the match rate: exactly 3 of every 7 vectors, identical in
			// every bucket (702/1638 leaves, 660/1540 parents, 219/511 blank leaves,
			// 483/1127 present leaves). A rate that constant across unrelated categories
			// is a per-suite split, never a property of nodes.
			unsupported++
			continue
		}
		tree := decodePadded(t, v)

		for x, wantHex := range v.TreeHashes {
			want, err := hex.DecodeString(wantHex)
			if err != nil {
				t.Fatalf("vector %d node %d: tree hash is not hex: %v", i, x, err)
			}

			got, err := TreeHash(tree, uint32(x), suite)
			if err != nil {
				t.Fatalf("vector %d node %d: %v", i, x, err)
			}

			if !bytes.Equal(got, want) {
				other, otherErr := treeHashVariant(tree, uint32(x), suite, false)
				note := "the other reading (parent_hash INCLUDED) does not match either"
				if otherErr == nil && bytes.Equal(other, want) {
					note = "the other reading (parent_hash INCLUDED) DOES match — the code has the flag backwards"
				}
				t.Errorf("vector %d node %d: tree hash =\n  %x\nwant\n  %s\n%s",
					i, x, got, wantHex, note)
			}
			checked++
		}
	}

	t.Logf("verified %d node tree hashes across %d trees; skipped %d vectors for unimplemented suites",
		checked, len(vectors)-unsupported, unsupported)
}

// TestWhichTreeHashReadingTheVectorsMean prints the answer to the open question, so that it
// is on the record even when the assertions above pass.
func TestWhichTreeHashReadingTheVectorsMean(t *testing.T) {
	vectors := loadTreeVectors(t)

	// Every parent node is tested under BOTH readings, rather than only each vector's root.
	//
	// The first version of this test looked at the root alone and stopped at the first
	// match. That was too small a sample: the root of a two-leaf tree matched with
	// parent_hash omitted while a deeper internal node of a four-leaf tree did not, which a
	// root-only sample cannot distinguish from "the whole input shape is wrong".
	//
	// Leaf nodes are excluded because both readings compute them identically — including
	// them would only inflate both totals and hide the answer.
	omitRoot, omitOther, includeRoot, includeOther := 0, 0, 0, 0
	omitMiss, includeMiss := 0, 0

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		tree := decodePadded(t, v)
		rootIndex := len(tree) - 1

		for x, wantHex := range v.TreeHashes {
			if IsLeaf(uint32(x)) {
				continue
			}
			want, err := hex.DecodeString(wantHex)
			if err != nil {
				t.Fatal(err)
			}

			omit, err := treeHashVariant(tree, uint32(x), suite, true)
			if err != nil {
				t.Fatal(err)
			}
			include, err := treeHashVariant(tree, uint32(x), suite, false)
			if err != nil {
				t.Fatal(err)
			}

			isRoot := x == rootIndex
			if bytes.Equal(omit, want) {
				if isRoot {
					omitRoot++
				} else {
					omitOther++
				}
			} else {
				omitMiss++
			}

			if bytes.Equal(include, want) {
				if isRoot {
					includeRoot++
				} else {
					includeOther++
				}
			} else {
				includeMiss++
			}
		}
	}

	t.Logf("parent node hashes — OMITTED parent_hash: root %d/%d, non-root %d/%d | "+
		"INCLUDED parent_hash: root %d/%d, non-root %d/%d",
		omitRoot, omitRoot+includeMiss+omitMiss-includeMiss, omitOther, omitOther+omitMiss,
		includeRoot, includeRoot+includeMiss, includeOther, includeOther+omitMiss)

	if omitRoot == 0 && omitOther == 0 && includeRoot == 0 && includeOther == 0 {
		t.Fatal("neither reading reproduced ANY published parent hash, so the input is " +
			"shaped differently than §7.8 as read here — the field order or the leaf " +
			"encoding must be wrong, not just the parent_hash rule")
	}
}

func equalUint32s(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
