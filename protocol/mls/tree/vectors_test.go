package tree

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The official vectors are not vendored; see protocol/mls/crypto for why. Skip when absent.

type treeMathVector struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []*uint32 `json:"left"`
	Right   []*uint32 `json:"right"`
	Parent  []*uint32 `json:"parent"`
	Sibling []*uint32 `json:"sibling"`
}

// TestTreeMathAgainstOfficialVectors checks every index relation for every tree size the
// vectors cover.
//
// This is the whole of M3's arithmetic, and it is worth being complete about: a single
// wrong parent index would make a path secret reach the wrong subtree, and the failure
// would surface much later as a member who simply cannot decrypt anything — with no hint
// that the cause was an integer.
func TestTreeMathAgainstOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "tree-math.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []treeMathVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("tree-math.json is not valid JSON: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("the vector file is empty")
	}

	relations := 0
	for _, v := range vectors {
		if !IsPowerOfTwo(v.NLeaves) {
			t.Errorf("vector with %d leaves is not a power of two; the array layout in this "+
				"package assumes one and this case needs handling", v.NLeaves)
			continue
		}

		if got, err := NumNodes(v.NLeaves); err != nil || got != v.NNodes {
			t.Errorf("n_leaves=%d: NumNodes = %d (err %v), want %d", v.NLeaves, got, err, v.NNodes)
		}
		if got, err := Root(v.NLeaves); err != nil || got != v.Root {
			t.Errorf("n_leaves=%d: Root = %d (err %v), want %d", v.NLeaves, got, err, v.Root)
		}

		nNodes, err := NumNodes(v.NLeaves)
		if err != nil {
			t.Fatal(err)
		}
		if uint32(len(v.Left)) != nNodes || uint32(len(v.Right)) != nNodes ||
			uint32(len(v.Parent)) != nNodes || uint32(len(v.Sibling)) != nNodes {
			t.Errorf("n_leaves=%d: the vector's arrays are not %d long", v.NLeaves, nNodes)
			continue
		}

		for x := uint32(0); x < nNodes; x++ {
			checkNode(t, v, x, "left", v.Left[x], func() (uint32, bool) { return Left(x) })
			checkNode(t, v, x, "right", v.Right[x], func() (uint32, bool) { return Right(x) })
			checkNode(t, v, x, "parent", v.Parent[x], func() (uint32, bool) { return Parent(x, v.NLeaves) })
			checkNode(t, v, x, "sibling", v.Sibling[x], func() (uint32, bool) { return Sibling(x, v.NLeaves) })
			relations += 4
		}

		// The direct path and copath are not in the vectors, so they are checked by
		// property instead: every member's path must end at the root, and walking the
		// copath from each member must reach every other member's subtree exactly once.
		for leaf := uint32(0); leaf < v.NLeaves; leaf++ {
			x := leafToNode(leaf)
			path, err := DirectPath(x, v.NLeaves)
			if err != nil {
				t.Fatalf("n_leaves=%d leaf %d: DirectPath: %v", v.NLeaves, leaf, err)
			}
			// A single-leaf tree's member IS the root, so an empty direct path is correct
			// there — and only there. The first version of this check treated the empty
			// path as a failure, which is the kind of assertion bug that makes a correct
			// implementation look broken.
			if v.NLeaves == 1 {
				if len(path) != 0 {
					t.Errorf("n_leaves=1: the direct path should be empty, got %v", path)
				}
			} else if len(path) == 0 || path[len(path)-1] != v.Root {
				t.Errorf("n_leaves=%d leaf %d: the direct path %v does not end at the root %d",
					v.NLeaves, leaf, path, v.Root)
			}

			copath, err := Copath(x, v.NLeaves)
			if err != nil {
				t.Fatalf("n_leaves=%d leaf %d: Copath: %v", v.NLeaves, leaf, err)
			}
			if len(copath) != len(path) {
				t.Errorf("n_leaves=%d leaf %d: the copath has %d nodes but the path has %d",
					v.NLeaves, leaf, len(copath), len(path))
			}
		}
	}

	t.Logf("verified %d index relations across %d tree sizes", relations, len(vectors))
}

func checkNode(t *testing.T, v treeMathVector, x uint32, name string, want *uint32, got func() (uint32, bool)) {
	t.Helper()

	value, ok := got()
	switch {
	case want == nil && ok:
		t.Errorf("n_leaves=%d node %d: %s = %d, want none", v.NLeaves, x, name, value)
	case want != nil && !ok:
		t.Errorf("n_leaves=%d node %d: %s = none, want %d", v.NLeaves, x, name, *want)
	case want != nil && value != *want:
		t.Errorf("n_leaves=%d node %d: %s = %d, want %d", v.NLeaves, x, name, value, *want)
	}
}

// leafToNode maps leaf index i to node index 2i, which is the convention the whole layout
// rests on.
func leafToNode(leaf uint32) uint32 { return 2 * leaf }
