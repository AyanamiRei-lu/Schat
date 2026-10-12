package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/secrettree"
	"github.com/schat/schat/protocol/mls/tree"
)

// The whole path, end to end: two members converge on an epoch through a commit, and then one
// of them sends a message the other reads.
//
// This is the test that says whether the group machinery is usable at all. Everything before it
// checked a stage — a tree, a key schedule, a ratchet, a codec — and each of those was verified
// against vectors or properties. What none of them checked is that the SECRET they agree on is
// the same secret, and that a message sealed under one side's view of it opens under the
// other's. A mistake in how the encryption secret flows from the key schedule into the secret
// tree would leave every stage correct and no message readable.
//
// The secret tree here is built from the epoch's encryption secret as the key schedule produced
// it, not from a value the test chose — which is the difference between checking the ratchet
// and checking the wiring.

func TestMembersExchangeAMessageAfterConverging(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")

	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

	// A commits a self-update, which moves both members to epoch 1.
	created, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
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
		t.Fatalf("CreateCommit: %v", err)
	}

	contextBytes, err := f.epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	originalHashes, err := tree.TreeHashes(f.epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	bNext, err := f.epoch.ProcessCommit(created.AsInput([]byte(aPublic), nil,
		func(member uint32, ct tree.HPKECiphertext) ([]byte, bool) {
			if member != 2 {
				return nil, false
			}
			secret, err := crypto.DecryptWithLabel(f.bLeafPriv, "UpdatePathNode", contextBytes, ct.KemOutput, ct.Ciphertext, suiteUnderTest)
			if err != nil {
				return nil, false
			}
			return secret, true
		}, originalHashes, nil))
	if err != nil {
		t.Fatalf("B could not process the commit: %v", err)
	}

	// Both sides now hold an encryption secret. If they differ, nothing below can work — and
	// this assertion localises that, rather than leaving it to surface as a decryption failure.
	if !bytes.Equal(bNext.Secrets.EncryptionSecret, created.Next.Secrets.EncryptionSecret) {
		t.Fatal("the two members disagree about the epoch's encryption secret")
	}

	// A builds the secret tree from that secret and seals a message with its own leaf's ratchet.
	aTree, err := secrettree.New(created.Next.Secrets.EncryptionSecret, 2, suiteUnderTest)
	if err != nil {
		t.Fatalf("A's secret tree: %v", err)
	}
	aRatchet, err := aTree.ApplicationRatchet(0)
	if err != nil {
		t.Fatal(err)
	}

	senderDataKey := bytes.Repeat([]byte{0x42}, suiteUnderTest.HashSize())

	senderData := messages.SenderData{LeafIndex: 0, Generation: 0}
	copy(senderData.ReuseGuard[:], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	sealed, err := SealApplication(SealApplicationInput{
		GroupID:           created.Next.Context.GroupID,
		Epoch:             created.Next.Number,
		AuthenticatedData: nil,
		Ratchet:           aRatchet,
		SenderData:        senderData,
		SenderDataSecret:  senderDataKey,
		Plaintext:         []byte("first group message"),
		Seal:              stdAESSeal,
		AdvanceRatchet:    true,
	})
	if err != nil {
		t.Fatalf("SealApplication: %v", err)
	}

	// B builds ITS OWN tree from ITS OWN epoch state — not from A's — and reads the message.
	bTree, err := secrettree.New(bNext.Secrets.EncryptionSecret, 2, suiteUnderTest)
	if err != nil {
		t.Fatalf("B's secret tree: %v", err)
	}

	opened, err := OpenApplication(OpenApplicationInput{
		Message:          sealed,
		ExpectedEpoch:    bNext.Number,
		ExpectedGroupID:  bNext.Context.GroupID,
		Tree:             bTree,
		SenderDataSecret: senderDataKey,
		Open:             stdAESOpen,
	})
	if err != nil {
		t.Fatalf("B could not read the message: %v", err)
	}

	if string(opened.Plaintext) != "first group message" {
		t.Fatalf("B read %q", opened.Plaintext)
	}
	if opened.SenderData.LeafIndex != 0 {
		t.Fatalf("B attributes the message to leaf %d, want 0", opened.SenderData.LeafIndex)
	}

	// A third party with a different epoch secret cannot read it. This is the negative that
	// says the message is actually protected rather than merely encoded.
	outsiderTree, err := secrettree.New(bytes.Repeat([]byte{0x99}, suiteUnderTest.HashSize()), 2, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenApplication(OpenApplicationInput{
		Message:          sealed,
		ExpectedEpoch:    bNext.Number,
		ExpectedGroupID:  bNext.Context.GroupID,
		Tree:             outsiderTree,
		SenderDataSecret: senderDataKey,
		Open:             stdAESOpen,
	}); err == nil {
		t.Fatal("a member holding a different epoch secret read the message")
	}

	t.Logf("A and B converged on epoch %d and exchanged a message through their own secret trees",
		bNext.Number)
}
