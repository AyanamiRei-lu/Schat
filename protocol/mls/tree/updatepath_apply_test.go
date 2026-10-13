package tree

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// TestApplyUpdatePathReconstructsTheSendersTree closes the loop on M3b part three.
//
// The sender side was already exercised on its own; this test takes the path it produced,
// hands it to the receiver side, and checks the result the way a real member would: the
// receiver holds private keys only for the nodes its position covers, must derive the rest
// down the path, and must end up with a tree whose parent hashes verify against the tree
// that existed before the update.
//
// The last check is the strongest one available without an interoperability test: VerifyParentHashes
// walks the applied tree and recomputes every chain from the ORIGINAL hashes, so it fails if
// the new keys, the path order, the sibling selection or the root termination is wrong in any
// way. It is also exactly what a receiving client does before accepting a commit.

func TestApplyUpdatePathReconstructsTheSendersTree(t *testing.T) {
	tree, privateKeys := buildTwoLevelTree(t)

	// A real group's tree always has a consistent parent hash chain; the fixture built above
	// does not, because it only fills in keys. Stamping it first is not a convenience — using
	// a tree whose parent hashes are empty makes the verification below fail for the paths the
	// update did not touch, which looks like an update path bug and is a fixture bug.
	tree = stampParentHashes(t, tree)

	groupContext := []byte("a provisional group context")

	initial := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(initial); err != nil {
		t.Fatal(err)
	}

	originalHashes, err := TreeHashes(tree, suiteUnderTest)
	if err != nil {
		t.Fatalf("TreeHashes: %v", err)
	}

	const senderLeaf = 0
	result, err := GenerateUpdatePath(tree, senderLeaf, groupContext, initial, nil, suiteUnderTest)
	if err != nil {
		t.Fatalf("GenerateUpdatePath: %v", err)
	}

	// A receiver that holds the keys for the nodes its position covers. It is deliberately
	// NOT given every key: the point of the top-down walk is that a member opens the first
	// ciphertext it can and derives everything below, so a test that handed over all keys
	// would pass even if the derivation path were broken.
	receiverKeys := map[uint32][]byte{
		2: privateKeys[2], // the leaf itself, in the resolution of the first step
		5: privateKeys[5], // the parent covering the second step's copath subtree
	}

	applier := func(member uint32, ct HPKECiphertext) ([]byte, bool) {
		priv, ok := receiverKeys[member]
		if !ok {
			return nil, false
		}
		secret, err := crypto.DecryptWithLabel(priv, "UpdatePathNode", groupContext,
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		if err != nil {
			return nil, false
		}
		return secret, true
	}

	updated, err := ApplyUpdatePath(tree, senderLeaf, result.Path, applier, originalHashes, suiteUnderTest)
	if err != nil {
		t.Fatalf("ApplyUpdatePath: %v", err)
	}

	// The input must be untouched: a caller that rejects a commit after validating it still
	// has to hold the epoch it was validating against.
	if !bytes.Equal(tree[1].Parent.EncryptionKey, mustKey(t, "parent-1")) {
		t.Fatal("ApplyUpdatePath modified the tree it was given")
	}

	// Every path node carries the sender's new key.
	for i, node := range result.FilteredPath {
		if !bytes.Equal(updated[node].Parent.EncryptionKey, result.Path.Nodes[i].EncryptionKey) {
			t.Fatalf("node %d did not receive the sender's new key", node)
		}
	}

	// The sender's new leaf replaced its old one.
	if !bytes.Equal(updated[2*senderLeaf].Leaf.EncryptionKey, result.Path.LeafNode.EncryptionKey) {
		t.Fatal("the sender's leaf node was not replaced")
	}

	// And the whole tree now verifies against the pre-update hashes, which is the check a
	// receiving client performs before accepting the commit.
	if err := VerifyParentHashes(updated, originalHashes, suiteUnderTest); err != nil {
		t.Fatalf("the applied tree does not verify: %v", err)
	}

	t.Logf("applied the update path: %d path nodes replaced, parent hashes verify against the "+
		"pre-update tree, and the receiver used only %d of the %d keys in the tree",
		len(result.FilteredPath), len(receiverKeys), len(privateKeys))
}

func mustKey(t *testing.T, label string) []byte {
	t.Helper()
	_, pub := keyPairFor(t, label)
	return pub
}

// stampParentHashes gives every node a parent hash chain consistent with the tree's own
// hashes, which is the state any tree in a real group is in.
//
// Every leaf's path is walked because the chain is defined per path, and a node's value
// depends only on the node above it and its own sibling — so the results agree wherever the
// paths overlap, and the last write wins harmlessly.
func stampParentHashes(t *testing.T, tree Tree) Tree {
	t.Helper()

	leaves, err := LeavesForLayout(uint32(len(tree)))
	if err != nil {
		t.Fatalf("LeavesForLayout: %v", err)
	}

	// The tree's own hashes are the "original" ones here: nothing has been updated yet.
	hashes, err := TreeHashes(tree, suiteUnderTest)
	if err != nil {
		t.Fatalf("TreeHashes: %v", err)
	}

	out := make(Tree, len(tree))
	copy(out, tree)

	for leaf := uint32(0); leaf < leaves; leaf++ {
		node := 2 * leaf
		if int(node) >= len(out) || out[node] == nil {
			continue
		}

		path, err := FilteredDirectPath(out, node)
		if err != nil {
			t.Fatalf("FilteredDirectPath(%d): %v", node, err)
		}
		if len(path) == 0 {
			continue
		}

		newKeys := make(map[uint32][]byte, len(path))
		for _, pathNode := range path {
			newKeys[pathNode] = out[pathNode].Parent.EncryptionKey
		}

		assigned, err := PathParentHashes(out, leaf, newKeys, hashes, suiteUnderTest)
		if err != nil {
			t.Fatalf("PathParentHashes(leaf %d): %v", leaf, err)
		}

		for target, hash := range assigned {
			if target == node {
				leafCopy := *out[node].Leaf
				leafCopy.ParentHash = hash
				leafCopy.Source = LeafNodeSourceCommit
				out[node] = &Node{Type: NodeTypeLeaf, Leaf: &leafCopy}
				continue
			}
			parentCopy := *out[target].Parent
			parentCopy.ParentHash = hash
			out[target] = &Node{Type: NodeTypeParent, Parent: &parentCopy}
		}
	}

	return out
}
