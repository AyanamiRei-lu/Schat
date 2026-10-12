package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/tree"
)

// Adding a member, end to end.
//
// The Add path was written in pieces and none of it had ever been executed together: the
// KeyPackage codec, the proposal case, the tree extension, the leaf placement, the exclusion
// set, and the two commit paths. This test runs them as one, which is the only way to find the
// kind of defect that lives BETWEEN two pieces that are each right on their own — the sender
// placing a leaf the receiver does not, or the reverse.
//
// The assertion that matters most is the last one: A and B must derive byte-identical epoch
// secrets. Everything before it checks a single step; that one checks that the two sides ended
// up in the same place, which is what the confirmation tag exists to detect and what a test
// against one's own code cannot detect on its own.

func keyPackageFor(t *testing.T, label string) *messages.KeyPackage {
	t.Helper()

	priv, pub := signerFor("keypackage-" + label)
	_, leafPub := hpkeKeyFor(t, "leaf-"+label)
	_, initPub := hpkeKeyFor(t, "init-"+label)

	kp := &messages.KeyPackage{
		Version:     1,
		CipherSuite: uint16(suiteUnderTest),
		InitKey:     initPub,
		LeafNode: &tree.LeafNode{
			EncryptionKey: leafPub,
			SignatureKey:  pub,
			Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte(label)},
			Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        tree.LeafNodeSourceKeyPackage,
			Lifetime:      &tree.Lifetime{NotBefore: 0, NotAfter: 1 << 40},
		},
	}

	signature, err := messages.SignKeyPackage(kp, priv, suiteUnderTest)
	if err != nil {
		t.Fatalf("signing the KeyPackage: %v", err)
	}
	kp.Signature = signature
	return kp
}

func TestAddingAMemberProducesTheSameEpochOnBothSides(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")

	keyPackage := keyPackageFor(t, "member-c")

	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

	created, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		Proposals: []*messages.ProposalOrRef{{
			Type:     messages.ProposalOrRefTypeProposal,
			Proposal: &messages.Proposal{Type: messages.ProposalTypeAdd, Add: &messages.Add{KeyPackage: keyPackage}},
		}},
		NewLeafNode: &tree.LeafNode{
			EncryptionKey: newLeafPub,
			SignatureKey:  aPublic,
			Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
			Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        tree.LeafNodeSourceUpdate,
		},
		PathSecret: pathSecret,
	})
	if err != nil {
		t.Fatalf("the sender could not create an Add commit: %v", err)
	}

	// Two leaves were taken, so the tree had to grow: four leaves, seven nodes.
	if len(created.Next.Tree) != 7 {
		t.Fatalf("after adding a member the sender's tree has %d nodes, want 7 (four leaves)",
			len(created.Next.Tree))
	}

	// The new member is at the RIGHT EDGE: leaf 3, which is node 6.
	if created.Next.Tree[6] == nil || created.Next.Tree[6].Leaf == nil {
		t.Fatal("the sender's tree does not hold the new member's leaf at the right edge")
	}
	if !bytes.Equal(created.Next.Tree[6].Leaf.EncryptionKey, keyPackage.LeafNode.EncryptionKey) {
		t.Fatal("the sender placed a leaf that is not the one the KeyPackage describes")
	}
	// The other leaf of the new level must be blank: only one member was added.
	if created.Next.Tree[4] != nil {
		t.Fatal("adding one member filled two leaf slots")
	}

	// The new member must receive NO path secret. It learns the epoch through its Welcome, so a
	// ciphertext addressed to it would hand key material to somebody who is not yet in the epoch
	// it belongs to.
	path := created.Content.Commit.Path
	if path == nil || len(path.Nodes) != 1 {
		t.Fatalf("the sender's path has %v nodes, want 1 — the old root; the new root and the new level are blank and are skipped", path)
	}
	for i, node := range path.Nodes {
		// Node 1's copath is B's leaf, which must be reached; node 3's copath subtree holds
		// only the new member, which must not be.
		want := 1
		if i == 1 {
			want = 0
		}
		if len(node.EncryptedPathSecret) != want {
			t.Fatalf("path node %d carries %d ciphertexts, want %d — the new member must be "+
				"excluded from the path", i, len(node.EncryptedPathSecret), want)
		}
	}

	// B receives it.
	contextBytes, err := f.epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	originalHashes, err := tree.TreeHashes(f.epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	opened := 0
	bApplier := func(_ uint32, ct tree.HPKECiphertext) ([]byte, bool) {
		secret, err := crypto.DecryptWithLabel(f.bLeafPriv, "UpdatePathNode", contextBytes, ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		if err != nil {
			return nil, false
		}
		opened++
		return secret, true
	}

	next, err := f.epoch.ProcessCommit(created.AsInput([]byte(aPublic), nil, bApplier,
		originalHashes, nil))
	if err != nil {
		t.Fatalf("the receiver rejected a correct Add commit: %v", err)
	}

	// B must have built the same tree, including the same placement of the new member.
	if len(next.Tree) != len(created.Next.Tree) {
		t.Fatalf("the two sides disagree about the tree size: %d nodes against %d",
			len(next.Tree), len(created.Next.Tree))
	}
	if next.Tree[6] == nil {
		t.Fatal("the receiver did not place the new member where the sender did")
	}
	if !bytes.Equal(next.Context.TreeHash, created.Next.Context.TreeHash) {
		t.Fatal("the two sides disagree about the new tree hash")
	}

	// And the check that subsumes all the others.
	if !bytes.Equal(next.Secrets.EncryptionSecret, created.Next.Secrets.EncryptionSecret) {
		t.Fatal("the two sides derived different epoch secrets from the same commit")
	}
	if !bytes.Equal(next.Secrets.ConfirmationKey, created.Next.Secrets.ConfirmationKey) {
		t.Fatal("the two sides derived different confirmation keys")
	}
	if !bytes.Equal(next.Transcript.Interim, created.Next.Transcript.Interim) {
		t.Fatal("the two sides disagree about the interim transcript hash")
	}

	// The receiver's own path secret had to be opened for any of this to hold, so a test that
	// passed with zero openings would be exercising nothing.
	if opened == 0 {
		t.Fatal("the receiver never opened its path secret")
	}

	t.Logf("added a member: tree grew to %d nodes, the new leaf is at node 6, %d ciphertexts "+
		"were sent and both sides derived the same epoch", len(next.Tree), opened)
}
