package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/tree"
)

// Two Adds in ONE commit: does the sender's tree match the receiver's?
//
// The sender and the receiver do not apply proposals the same way. The sender calls
// applyProposalEffects, which collects every removal and every addition, applies the removals
// first, and re-checks whether the tree needs extending before EACH addition. The receiver has
// its own inline copy that walks the proposals in the order they arrived and checks for
// extension once.
//
// With one proposal the two produce the same tree, which is why every existing test passes. With
// two they need not: the second addition happens after the tree has grown, and whether the
// receiver notices depends on whether it re-checks. This test is the measurement that says
// whether that difference is reachable — and it comes BEFORE any attempt to unify the two,
// because "these two implementations differ" is not the same claim as "the difference matters".

func TestTwoAddsInOneCommitAgreeBetweenSides(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")

	// Two distinct KeyPackages, from two distinct identities.
	keyPackageC, _ := memberCKeyPackage(t)
	keyPackageD := keyPackageFor(t, "member-d")

	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

	created, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		Proposals: []*messages.ProposalOrRef{
			{
				Type:     messages.ProposalOrRefTypeProposal,
				Proposal: &messages.Proposal{Type: messages.ProposalTypeAdd, Add: &messages.Add{KeyPackage: keyPackageC}},
			},
			{
				Type:     messages.ProposalOrRefTypeProposal,
				Proposal: &messages.Proposal{Type: messages.ProposalTypeAdd, Add: &messages.Add{KeyPackage: keyPackageD}},
			},
		},
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
		t.Fatalf("the commit with two Adds could not be created: %v", err)
	}

	// The sender must have placed both members.
	if len(created.AddedLeaves) != 2 {
		t.Fatalf("the sender placed %d new members, want 2", len(created.AddedLeaves))
	}

	// The receiver, using the leaf key it already holds.
	bEpoch := f.epoch
	bEpoch.PrivateNodes = map[uint32][]byte{2: f.bLeafPriv}

	next := processAsMember(t, bEpoch, 1, created, []byte(aPublic), nil)

	if len(next.Tree) != len(created.Next.Tree) {
		t.Fatalf("the two sides built trees of different sizes: %d against %d",
			len(next.Tree), len(created.Next.Tree))
	}
	if !bytes.Equal(next.Context.TreeHash, created.Next.Context.TreeHash) {
		t.Fatal("the two sides built DIFFERENT TREES from the same commit with two Adds, so the " +
			"receiver's proposal handling does not match the sender's")
	}
	if !bytes.Equal(next.Secrets.EpochAuthenticator, created.Next.Secrets.EpochAuthenticator) {
		t.Fatal("the two sides derived different epochs from the same commit with two Adds")
	}

	t.Logf("both sides placed %v and reached epoch %d", created.AddedLeaves, next.Number)
}
