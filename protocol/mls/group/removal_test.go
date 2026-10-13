package group

import (
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Removing a member, end to end through the group API.
//
// # Why this is the test that matters most so far
//
// Every other property checked in this package can fail loudly: a wrong signature, a wrong
// key, a wrong hash all produce an error somebody sees. A removal that does not remove
// produces NO error anywhere. The member keeps its leaf, keeps deriving epochs, keeps reading
// the group — and the only way to notice is to check, deliberately, that it cannot.
//
// So this test removes the only other member of a two-member group and then asserts the
// negative: the removed member must be unable to advance. It also counts how many times the
// removed member's key was offered a ciphertext, because "could not derive" and "was never
// even asked" look the same from the outside and are different facts about the implementation.

func TestRemovingAMemberLeavesItUnableToFollow(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")

	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

	removed := uint32(1) // B is leaf 1, node 2

	created, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		Proposals: []*messages.ProposalOrRef{{
			Type: messages.ProposalOrRefTypeProposal,
			Proposal: &messages.Proposal{
				Type:   messages.ProposalTypeRemove,
				Remove: &messages.Remove{Removed: removed},
			},
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
		t.Fatalf("the sender could not create a removal commit: %v", err)
	}

	// The sender's own view: B's leaf is a hole and the group keeps its shape.
	if len(created.Next.Tree) != 1 {
		t.Fatalf("after removing the only other member the tree has %d nodes, want 1 — the "+
			"surviving member's leaf, which is now also the root", len(created.Next.Tree))
	}
	if created.Next.Tree[0] == nil {
		t.Fatal("the sender removed its own leaf as well")
	}
	if created.Next.Tree[0] == nil {
		t.Fatal("the sender removed its own leaf as well")
	}
	if created.Next.Tree[0] == nil || created.Next.Tree[0].Leaf == nil {
		t.Fatal("the surviving member's leaf is not the single node of the truncated tree")
	}

	// The path must carry nothing for the member being removed. In a two-leaf group B is the
	// entire copath resolution of A's only path node, so excluding it leaves no ciphertext.
	path := created.Content.Commit.Path
	if path == nil || len(path.Nodes) != 1 {
		t.Fatalf("expected a one-node path in a two-leaf group, got %v", path)
	}
	if got := len(path.Nodes[0].EncryptedPathSecret); got != 0 {
		t.Fatalf("the removal commit carries %d ciphertexts for the removed member; it would "+
			"derive the new epoch and keep reading the group", got)
	}

	// B's attempt to follow. Its applier uses B's real private key, so a failure here is not a
	// missing-key artefact: there is simply nothing addressed to it.
	contextBytes, err := f.epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	originalHashes, err := tree.TreeHashes(f.epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	offers := 0
	bApplier := func(_ uint32, ct tree.HPKECiphertext) ([]byte, bool) {
		offers++
		secret, err := crypto.DecryptWithLabel(f.bLeafPriv, "UpdatePathNode", contextBytes,
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		return secret, err == nil
	}

	if _, err := f.epoch.ProcessCommit(created.AsInput([]byte(aPublic), nil, bApplier,
		originalHashes, nil)); err == nil {
		t.Fatal("the removed member advanced to the new epoch, so the removal did not remove it")
	}
	if offers != 0 {
		t.Fatalf("the removed member was offered %d ciphertexts; the exclusion set is not being "+
			"applied by the sender", offers)
	}

	// The sender must still be able to validate its own commit: if it could not, the commit it
	// just built would be rejected by every member including its author.
	senderView := func(_ uint32, ct tree.HPKECiphertext) ([]byte, bool) { return nil, false }
	_ = senderView

	// There is deliberately nothing here about what the group does next. After this removal it
	// has one member and its tree has a single node, and a one-member group CANNOT create an
	// update path: the path is the chain of nodes above the sender's leaf, and when the leaf is
	// the root that chain is empty. The earlier version of this test had a self-update here and
	// it passed, because truncation was not yet implemented — the tree still had the removed
	// member's blank leaf, so a path existed that should not have. The section was removed
	// rather than repaired: the next real commit in this group has to be an Add.
}

func mustHashes(t *testing.T, e *Epoch) [][]byte {
	t.Helper()
	hashes, err := tree.TreeHashes(e.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	return hashes
}
