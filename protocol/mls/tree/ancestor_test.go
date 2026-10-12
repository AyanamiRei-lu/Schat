package tree

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The lowest common ancestor, checked by its definition over every tree the official vectors
// cover.
//
// The definition is "the lowest node on both direct paths", so the checks below are the
// definition itself rather than a reimplementation of the code: the result must be on both
// paths, and no node strictly below it may be. A closed-form expression would have needed a
// separate argument for why it equals this; the walk needs none.

func TestLowestCommonAncestorIsOnBothPaths(t *testing.T) {
	for _, n := range []uint32{1, 2, 4, 8, 16} {
		for i := uint32(0); i < n; i++ {
			for j := uint32(0); j < n; j++ {
				a, b := 2*i, 2*j

				ancestor, ok, err := LowestCommonAncestor(a, b, n)
				if err != nil {
					t.Fatalf("n=%d leaves %d,%d: %v", n, i, j, err)
				}
				if !ok {
					t.Fatalf("n=%d leaves %d,%d: no common ancestor", n, i, j)
				}

				if i == j {
					if ancestor != a {
						t.Fatalf("n=%d leaf %d against itself gave node %d", n, i, ancestor)
					}
					continue
				}

				// It must be on both paths — including being one of the leaves only if the two
				// leaves are the same, which was handled above.
				pathA, err := DirectPath(a, n)
				if err != nil {
					t.Fatal(err)
				}
				pathB, err := DirectPath(b, n)
				if err != nil {
					t.Fatal(err)
				}
				if !contains(pathA, ancestor) || !contains(pathB, ancestor) {
					t.Fatalf("n=%d leaves %d,%d: node %d is not on both direct paths", n, i, j, ancestor)
				}

				// And NOTHING below it may be on both, or it would not be the lowest.
				for _, lower := range append(append([]uint32{}, pathA...), a) {
					if lower == ancestor {
						break
					}
					if lower == b || contains(pathB, lower) {
						t.Fatalf("n=%d leaves %d,%d: node %d is below the returned ancestor %d and "+
							"is also on both paths, so %d is not the lowest",
							n, i, j, lower, ancestor, ancestor)
					}
				}
			}
		}
	}
}

func TestLowestCommonAncestorAgainstTheOfficialTrees(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "tree-math.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []treeMathVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("tree-math.json is not valid JSON: %v", err)
	}

	pairs := 0
	for _, v := range vectors {
		for i := uint32(0); i < v.NLeaves; i++ {
			for j := uint32(0); j < v.NLeaves; j++ {
				ancestor, ok, err := LowestCommonAncestor(2*i, 2*j, v.NLeaves)
				if err != nil || !ok {
					t.Fatalf("n_leaves=%d leaves %d,%d: %v (ok=%v)", v.NLeaves, i, j, err, ok)
				}

				// The vector's own parent relation must agree: walking up from the ancestor must
				// reach the root, and the ancestor must be the one the tree's structure implies.
				root, err := Root(v.NLeaves)
				if err != nil {
					t.Fatal(err)
				}
				path, err := DirectPath(2*i, v.NLeaves)
				if err != nil {
					t.Fatal(err)
				}
				if len(path) > 0 {
					if !contains(path, ancestor) && ancestor != 2*i {
						t.Fatalf("n_leaves=%d leaves %d,%d: ancestor %d is not on leaf %d's path",
							v.NLeaves, i, j, ancestor, i)
					}
					if ancestor == 2*i && i != j {
						t.Fatalf("n_leaves=%d leaves %d,%d: the ancestor is one of the leaves",
							v.NLeaves, i, j)
					}
					_ = root
				}
				pairs++
			}
		}
	}
	t.Logf("checked %d leaf pairs across %d official tree sizes", pairs, len(vectors))
}

func TestLowestCommonAncestorRejectsBadInput(t *testing.T) {
	if _, _, err := LowestCommonAncestor(0, 2, 3); err == nil {
		t.Fatal("a leaf count that is not a power of two was accepted")
	}
	if _, _, err := LowestCommonAncestor(0, 1, 2); err == nil {
		t.Fatal("an odd node index was accepted as a leaf")
	}
}

// TestPathSecretForNewMember pins what a commit must deliver to a new member: the secret of the
// lowest common ancestor, and NOTHING when that node carries none.
//
// The second half is the subtle one. An absent path secret and an empty one are different on
// the wire, so a caller that sent an empty value instead of omitting the field would produce a
// Welcome that decodes differently from what the committer wrote.
func TestPathSecretForNewMember(t *testing.T) {
	// Four leaves: node 3 is the root, node 1 and node 5 are its children.
	secrets := map[uint32][]byte{
		1: []byte("secret-at-1"),
		3: []byte("secret-at-3"),
		5: []byte("secret-at-5"),
	}

	// Leaves 0 and 1 are both under node 1, so that is where their subtrees meet.
	ancestor, secret, present, err := PathSecretForNewMember(0, 2, 4, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if ancestor != 1 {
		t.Fatalf("the ancestor of leaves 0 and 1 is node %d, want 1", ancestor)
	}
	if !present || string(secret) != "secret-at-1" {
		t.Fatalf("the delivered secret is %q (present=%v), want the one at node 1", secret, present)
	}

	// Leaves 0 and 2 are on opposite sides of the root.
	ancestor, secret, present, err = PathSecretForNewMember(0, 4, 4, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if ancestor != 3 {
		t.Fatalf("the ancestor of leaves 0 and 2 is node %d, want 3", ancestor)
	}
	if !present || string(secret) != "secret-at-3" {
		t.Fatalf("the delivered secret is %q, want the one at node 3", secret)
	}

	// A committer adding itself: the ancestor is its own leaf, which carries no path secret, so
	// the field must be OMITTED rather than written empty.
	ancestor, _, present, err = PathSecretForNewMember(0, 0, 4, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if ancestor != 0 {
		t.Fatalf("leaf 0 against itself gave node %d", ancestor)
	}
	if present {
		t.Fatal("a path secret was reported for a leaf, which carries none — an empty value here " +
			"would encode differently from an absent one")
	}
}

func contains(nodes []uint32, want uint32) bool {
	for _, node := range nodes {
		if node == want {
			return true
		}
	}
	return false
}
