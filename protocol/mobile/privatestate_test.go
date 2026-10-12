package mobile

import (
	"encoding/json"
	"testing"
)

// What a joining member's private state actually contains.
//
// The member can join and can read the group, and cannot apply a commit — and the failure looks
// like a confirmation tag mismatch, which says nothing about where it started. This reads the
// snapshot and reports the node indices the member holds keys for.
//
// Expected, if the derivation runs: the member's own leaf (node index 2*leaf) plus the nodes on
// its direct path above the lowest common ancestor with the committer. For leaf 1 in a
// two-member group that is node 2 alone, because the ancestor IS the root and there is nothing
// above it.
//
// An empty map means the derivation never ran, and the commit failure then has nothing to do
// with confirmation tags at all.

func privateNodeIndices(t *testing.T, stateJSON string) []string {
	t.Helper()

	var raw struct {
		PrivateNodes map[string]string `json:"private_nodes"`
	}
	if err := json.Unmarshal([]byte(stateJSON), &raw); err != nil {
		t.Fatalf("the snapshot is not valid JSON: %v", err)
	}

	keys := make([]string, 0, len(raw.PrivateNodes))
	for node := range raw.PrivateNodes {
		keys = append(keys, node)
	}
	return keys
}

func TestAJoiningMemberHoldsItsOwnPrivateNodes(t *testing.T) {
	_, _, aliceState, bobState := aliceAndState(t)

	aliceNodes := privateNodeIndices(t, aliceState)
	bobNodes := privateNodeIndices(t, bobState)

	t.Logf("after joining: committer holds nodes %v", aliceNodes)
	t.Logf("after joining: joiner    holds nodes %v", bobNodes)

	if len(bobNodes) == 0 {
		t.Fatal("the joining member holds NO private nodes, so it cannot decrypt a path secret " +
			"addressed to it and cannot apply any commit — the confirmation tag mismatch is a " +
			"symptom of this, not the cause")
	}

	// The member's own leaf is node 2*1 = 2. Without it there is nothing to start from.
	found := false
	for _, node := range bobNodes {
		if node == "2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the joining member holds nodes %v but not its own leaf (node 2), so it has no "+
			"key to decrypt anything addressed to it", bobNodes)
	}
}
