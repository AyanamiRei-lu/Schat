package tree

import (
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// The exclusion set, which is what makes a removal a removal.
//
// A removal commit updates the sender's path, and path secrets travel to the resolution of
// each copath node. If the member being removed is in one of those resolutions — and in a
// two-leaf group it is the ONLY member of it — then sending it a path secret hands it the new
// epoch's keys and the removal accomplishes nothing, with nothing anywhere reporting a
// problem.
//
// So the property is a negative one: the removed member must receive NO ciphertext and be
// unable to derive anything. A test that only checked "the commit applies" would pass with the
// removed member still reading the group.

func hpkeKey(t *testing.T, label string) (priv, pub []byte) {
	t.Helper()
	seed := make([]byte, 32)
	copy(seed, []byte(label))
	priv, pub, err := crypto.DeriveKeyPair(seed, suiteUnderTest)
	if err != nil {
		t.Fatalf("DeriveKeyPair(%s): %v", label, err)
	}
	return priv, pub
}

// twoLeafTree returns a group of two members: A at leaf 0 and B at leaf 1 (node 2).
func twoLeafTree(t *testing.T) (Tree, []byte) {
	t.Helper()

	_, aPub := hpkeKey(t, "leaf-a")
	bPriv, bPub := hpkeKey(t, "leaf-b")
	_, rootPub := hpkeKey(t, "root")

	ratchet := make(Tree, 3)
	ratchet[0] = leafNode(aPub)
	ratchet[2] = leafNode(bPub)
	ratchet[1] = &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: rootPub}}
	return ratchet, bPriv
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

// TestRemovedMemberReceivesNoPathSecret is the property that decides whether removing someone
// removes them.
func TestRemovedMemberReceivesNoPathSecret(t *testing.T) {
	ratchet, bPriv := twoLeafTree(t)

	originalHashes, err := TreeHashes(ratchet, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	pathSecret := randomSecret(t)

	// A self-update by A that also removes B. B is node 2, and it is the entire copath
	// resolution of A's only path node, so excluding it leaves nothing to encrypt to.
	result, err := GenerateUpdatePath(ratchet, 0, []byte("group context"), pathSecret, []uint32{2}, suiteUnderTest)
	if err != nil {
		t.Fatalf("GenerateUpdatePath: %v", err)
	}

	if len(result.Path.Nodes) != 1 {
		t.Fatalf("a two-leaf tree gave a path of %d nodes, want 1", len(result.Path.Nodes))
	}
	if got := len(result.Path.Nodes[0].EncryptedPathSecret); got != 0 {
		t.Fatalf("the removed member received %d ciphertexts; it is in the copath resolution and "+
			"must be excluded, or the removal leaves it able to derive the new epoch", got)
	}

	// The SENDER applies its own commit. It holds every path secret, so it supplies them by
	// node index — the case that used to fail: with no ciphertexts to key on, the sender had
	// no way to tell ApplyUpdatePath what the secrets were, and a commit removing the last
	// other member could not be created at all.
	senderSecrets := map[uint32][]byte{}
	for i, node := range result.FilteredPath {
		senderSecrets[node] = result.PathSecrets[i]
	}

	if _, err := ApplyUpdatePathExcluding(ratchet, 0, result.Path, map[uint32]bool{2: true},
		senderSecrets, nil, originalHashes, suiteUnderTest, nil); err != nil {
		t.Fatalf("the sender could not apply its own removal commit: %v", err)
	}

	// A receiver that does NOT know about the removal expects one ciphertext and must refuse,
	// rather than accepting a list that omitted a member it believed it should reach.
	if _, err := ApplyUpdatePathExcluding(ratchet, 0, result.Path, nil, nil, nil,
		originalHashes, suiteUnderTest, nil); err == nil {
		t.Fatal("a receiver that ignored the removal accepted a path with no ciphertext for a "+
			"member it still considered present, so the ciphertext count is not checked against "+
			"the filtered resolution", nil)
	}

	// And B itself has nothing to open: an applier holding B's real private key is never asked,
	// because there is no ciphertext addressed to it.
	calls := 0
	bApplier := func(_ uint32, ct HPKECiphertext) ([]byte, bool) {
		calls++
		secret, err := crypto.DecryptWithLabel(bPriv, "UpdatePathNode", []byte("group context"),
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		return secret, err == nil
	}

	// B holds no secret for the root-adjacent node and cannot derive one from above, which is
	// exactly the position a removed member is in.
	if _, err := ApplyUpdatePathExcluding(ratchet, 0, result.Path, map[uint32]bool{2: true},
		nil, bApplier, originalHashes, suiteUnderTest, nil); err == nil {
		t.Fatal("a member that could open nothing still advanced to the new epoch")
	}
	if calls != 0 {
		t.Fatalf("the removed member's key was tried %d times, so a ciphertext was addressed to "+
			"it after all", calls)
	}
}

// TestMemberNotExcludedDoesReceiveTheSecret is the control: without it, the test above would
// also pass if the exclusion were implemented as "never encrypt to anyone".
func TestMemberNotExcludedDoesReceiveTheSecret(t *testing.T) {
	ratchet, bPriv := twoLeafTree(t)

	originalHashes, err := TreeHashes(ratchet, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	result, err := GenerateUpdatePath(ratchet, 0, []byte("group context"), randomSecret(t), nil, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(result.Path.Nodes[0].EncryptedPathSecret); got != 1 {
		t.Fatalf("the copath resolution has one member but %d ciphertexts were produced", got)
	}

	opened := 0
	bApplier := func(_ uint32, ct HPKECiphertext) ([]byte, bool) {
		secret, err := crypto.DecryptWithLabel(bPriv, "UpdatePathNode", []byte("group context"),
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		if err != nil {
			return nil, false
		}
		opened++
		return secret, true
	}

	if _, err := ApplyUpdatePathExcluding(ratchet, 0, result.Path, nil, nil, bApplier,
		originalHashes, suiteUnderTest, nil); err != nil {
		t.Fatalf("a member that is still in the group could not follow the commit: %v", err)
	}
	if opened != 1 {
		t.Fatalf("B opened %d secrets, want exactly 1", opened)
	}
}

// TestASuppliedSecretMustMatchThePath guards the new input: a caller-supplied secret is
// trusted only after the published key is checked against it, so a wrong secret is an error
// rather than a tree whose keys nobody else can derive.
func TestASuppliedSecretMustMatchThePath(t *testing.T) {
	ratchet, _ := twoLeafTree(t)

	originalHashes, err := TreeHashes(ratchet, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	result, err := GenerateUpdatePath(ratchet, 0, []byte("group context"), randomSecret(t), nil, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	wrong := map[uint32][]byte{}
	for _, node := range result.FilteredPath {
		wrong[node] = randomSecret(t)
	}

	if _, err := ApplyUpdatePathExcluding(ratchet, 0, result.Path, nil, wrong, nil,
		originalHashes, suiteUnderTest, nil); err == nil {
		t.Fatal("a caller-supplied secret that does not derive the published key was accepted")
	}
}

// TestExcludedLeavesForCommit collects the leaves a commit adds or removes.
func TestExcludedLeavesForCommit(t *testing.T) {
	removed := uint32(1)
	excluded := ExcludedLeavesForCommit([]ProposalEffect{
		{RemovedLeaf: &removed},
		{AddedLeaves: []uint32{3, 4}},
	})

	// Removals and additions alike become NODE indices, which is what a resolution holds.
	for _, leaf := range []uint32{1, 3, 4} {
		if !excluded[2*leaf] {
			t.Fatalf("leaf %d (node %d) is not excluded", leaf, 2*leaf)
		}
	}
	if len(excluded) != 3 {
		t.Fatalf("the exclusion set has %d entries, want 3", len(excluded))
	}

	if got := ExcludedLeavesForCommit(nil); len(got) != 0 {
		t.Fatalf("a commit with no tree-changing proposals excluded %d nodes", len(got))
	}
}
