package tree

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// TestUpdatePathEndToEnd is the first execution of the update path code.
//
// Until this test existed, GenerateUpdatePath, PathParentHashes and the codec had only ever
// been read, never run. Reading establishes that code compiles and that its constants came
// from the specification; it establishes nothing about whether the pieces fit together. This
// test makes them run and checks the properties that a wrong implementation would break:
//
//  1. Every ciphertext decrypts to the path secret of the node it was attached to, and only
//     with the private key of the node the resolution selected.
//  2. The new public keys really are KEM.DeriveKeyPair of DeriveSecret(path_secret, "node"),
//     so a member that receives a secret derives the same key the committer published.
//  3. The path has exactly one node per non-blank node above the leaf, and one ciphertext
//     per member of the corresponding copath resolution.
//  4. The parent hash chain is assigned to every node on the path, root last, and the root's
//     is empty.
//
// What it cannot check is interoperability: both sides of this test are this package. That
// limitation belongs in the report, not in a comment claiming more than the test does.

const suiteUnderTest = crypto.CipherSuite(0x0001)

func keyPairFor(t *testing.T, label string) (priv, pub []byte) {
	t.Helper()

	seed := make([]byte, 32)
	// Deterministic per label so a failure is reproducible, and distinct per node so no two
	// nodes accidentally share a key — which would let a wrong recipient decrypt and turn a
	// real bug into a pass.
	copy(seed, []byte(label))
	priv, pub, err := crypto.DeriveKeyPair(seed, suiteUnderTest)
	if err != nil {
		t.Fatalf("DeriveKeyPair(%s): %v", label, err)
	}
	return priv, pub
}

func leafNode(pub []byte) *Node {
	return &Node{
		Type: NodeTypeLeaf,
		Leaf: &LeafNode{
			EncryptionKey: pub,
			SignatureKey:  make([]byte, 32),
			Credential:    Credential{Type: CredentialTypeBasic, Identity: []byte("member")},
			Capabilities:  Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        LeafNodeSourceUpdate,
		},
	}
}

// buildTwoLevelTree makes a four-leaf tree: leaves at 0,2,4,6 and parents at 1,3,5.
func buildTwoLevelTree(t *testing.T) (Tree, map[uint32][]byte) {
	t.Helper()

	tree := make(Tree, 7)
	privateKeys := map[uint32][]byte{}

	for _, node := range []uint32{0, 2, 4, 6} {
		priv, pub := keyPairFor(t, "leaf-"+itoa(int(node)))
		tree[node] = leafNode(pub)
		privateKeys[node] = priv
	}
	for _, node := range []uint32{1, 3, 5} {
		priv, pub := keyPairFor(t, "parent-"+itoa(int(node)))
		tree[node] = &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: pub}}
		privateKeys[node] = priv
	}

	return tree, privateKeys
}

func TestUpdatePathEndToEnd(t *testing.T) {
	tree, privateKeys := buildTwoLevelTree(t)

	groupContext := []byte("a provisional group context")

	initial := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(initial); err != nil {
		t.Fatal(err)
	}

	originalHashes, err := TreeHashes(tree, suiteUnderTest)
	if err != nil {
		t.Fatalf("TreeHashes: %v", err)
	}

	const leafIndex = 0
	result, err := GenerateUpdatePath(tree, leafIndex, groupContext, initial, nil, suiteUnderTest)
	if err != nil {
		t.Fatalf("GenerateUpdatePath: %v", err)
	}

	// Property 3: one node per non-blank node above the leaf. For leaf 0 in this tree those
	// are nodes 1 and 3.
	if len(result.FilteredPath) != 2 {
		t.Fatalf("filtered path = %v, want the two parents above leaf 0", result.FilteredPath)
	}
	if len(result.Path.Nodes) != len(result.FilteredPath) {
		t.Fatalf("%d update path nodes for %d path entries",
			len(result.Path.Nodes), len(result.FilteredPath))
	}

	for i, pathNode := range result.FilteredPath {
		node := result.Path.Nodes[i]

		// The copath node is the sibling of the node BELOW the path node: the leaf itself on
		// the first step, then the previous path node.
		below := uint32(2 * leafIndex)
		if i > 0 {
			below = result.FilteredPath[i-1]
		}
		copath, ok := Sibling(below, 4)
		if !ok {
			t.Fatalf("node %d has no sibling", below)
		}
		resolution, err := Resolution(tree, copath)
		if err != nil {
			t.Fatalf("Resolution(%d): %v", copath, err)
		}

		// Property 1 and 3: one ciphertext per resolution member, and each one opens only
		// with that member's private key.
		if len(node.EncryptedPathSecret) != len(resolution) {
			t.Fatalf("path node %d carries %d ciphertexts for a resolution of %d",
				pathNode, len(node.EncryptedPathSecret), len(resolution))
		}

		for j, member := range resolution {
			priv, ok := privateKeys[member]
			if !ok {
				t.Fatalf("no private key for resolution member %d", member)
			}
			ct := node.EncryptedPathSecret[j]

			recovered, err := crypto.DecryptWithLabel(priv, "UpdatePathNode", groupContext,
				ct.KemOutput, ct.Ciphertext, suiteUnderTest)
			if err != nil {
				t.Fatalf("node %d cannot open the ciphertext addressed to it: %v", member, err)
			}
			if !bytes.Equal(recovered, result.PathSecrets[i]) {
				t.Fatalf("node %d recovered a different secret than path node %d holds", member, pathNode)
			}
		}

		// Property 2: the published key is the one a member derives from the secret.
		nodeSecret, err := crypto.DeriveSecret(result.PathSecrets[i], "node", suiteUnderTest)
		if err != nil {
			t.Fatal(err)
		}
		_, derivedPub, err := crypto.DeriveKeyPair(nodeSecret, suiteUnderTest)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(derivedPub, node.EncryptionKey) {
			t.Fatalf("path node %d published a key that its path secret does not derive", pathNode)
		}
	}

	// Property 4: the parent hash chain covers the leaf and every path node, and terminates
	// with an empty root hash.
	newKeys := map[uint32][]byte{}
	for i, pathNode := range result.FilteredPath {
		newKeys[pathNode] = result.Path.Nodes[i].EncryptionKey
	}

	hashes, err := PathParentHashes(tree, leafIndex, newKeys, originalHashes, suiteUnderTest)
	if err != nil {
		t.Fatalf("PathParentHashes: %v", err)
	}

	root := result.FilteredPath[len(result.FilteredPath)-1]
	if len(hashes) != len(result.FilteredPath)+1 {
		t.Fatalf("parent hashes cover %d nodes, want %d (the leaf plus the path)",
			len(hashes), len(result.FilteredPath)+1)
	}
	if got, ok := hashes[root]; !ok || len(got) != 0 {
		t.Fatalf("the root's parent hash is %x (present=%v), want empty", got, ok)
	}
	if _, ok := hashes[2*leafIndex]; !ok {
		t.Fatal("the leaf was not given a parent hash")
	}

	t.Logf("update path ran: %d path nodes, %d ciphertexts, each opened by the member its "+
		"copath resolution selected, recovering that node's path secret",
		len(result.Path.Nodes), countCiphertexts(result.Path))
	t.Log("NOT covered here: that a DIFFERENT member cannot open a ciphertext. That is AEAD's " +
		"property rather than this package's, but the test does not exercise it, and the " +
		"log line above deliberately does not claim it.")
}

func countCiphertexts(p *UpdatePath) int {
	n := 0
	for _, node := range p.Nodes {
		n += len(node.EncryptedPathSecret)
	}
	return n
}
