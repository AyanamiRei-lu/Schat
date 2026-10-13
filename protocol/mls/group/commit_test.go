package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/schedule"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// The sender and receiver halves, run against each other.
//
// CreateCommit and ProcessCommit were written separately and neither had ever been executed
// together. Everything below exists to make them meet: the sender generates a path, encrypts
// it to the other member, signs and tags; the receiver opens its secret with a real private
// key, applies the path, and both sides must land on byte-identical epoch state.
//
// # What this test deliberately does not do
//
// It is a self-update: the sender refreshes its own key and removes nobody. The removal case
// needs the path's resolution to EXCLUDE the leaves being removed, and ApplyUpdatePath
// currently checks the ciphertext count against the raw resolution, so a removal commit would
// be rejected by the receiver for a reason that has nothing to do with its signature. That
// gap is real, it is understood, and it is left for the next change rather than papered over
// by loosening the check — a receiver that accepted a short ciphertext list would also accept
// one that omitted a member it should have reached.

// suiteUnderTest and signerFor are shared with epoch_test.go; only the HPKE key helper is new
// here, because the earlier tests held no private leaf keys — a commit that removes a member
// carries no path, so no path secret was ever opened.

func hpkeKeyFor(t *testing.T, label string) (priv, pub []byte) {
	t.Helper()
	seed := make([]byte, 32)
	copy(seed, []byte(label))
	priv, pub, err := crypto.DeriveKeyPair(seed, suiteUnderTest)
	if err != nil {
		t.Fatalf("DeriveKeyPair(%s): %v", label, err)
	}
	return priv, pub
}

type fixture struct {
	epoch     *Epoch
	commitSec []byte
	bLeafPriv []byte
}

// twoMemberGroup builds epoch 0 with A at leaf 0 and B at leaf 1, holding real key material.
func twoMemberGroup(t *testing.T) fixture {
	t.Helper()

	aSign, aVerify := signerFor("member-a")
	_ = aSign
	bSign, bVerify := signerFor("member-b")
	_ = bSign

	_, aLeafPub := hpkeKeyFor(t, "leaf-a")
	bLeafPriv, bLeafPub := hpkeKeyFor(t, "leaf-b")

	ratchet := make(tree.Tree, 3)
	ratchet[0] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: &tree.LeafNode{
		EncryptionKey: aLeafPub, SignatureKey: aVerify,
		Credential:   tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
		Capabilities: tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
		Source:       tree.LeafNodeSourceUpdate,
	}}
	ratchet[2] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: &tree.LeafNode{
		EncryptionKey: bLeafPub, SignatureKey: bVerify,
		Credential:   tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("B")},
		Capabilities: tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
		Source:       tree.LeafNodeSourceUpdate,
	}}
	_, parentPub := hpkeKeyFor(t, "parent-root")
	ratchet[1] = &tree.Node{Type: tree.NodeTypeParent, Parent: &tree.ParentNode{EncryptionKey: parentPub}}

	initialTreeHash, err := treeHashOf(ratchet, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	context := schedule.GroupContext{
		Version:                 schedule.ProtocolVersion,
		CipherSuite:             uint16(suiteUnderTest),
		GroupID:                 []byte("group-1"),
		Epoch:                   0,
		TreeHash:                initialTreeHash,
		ConfirmedTranscriptHash: []byte{},
	}

	initSecret := make([]byte, suiteUnderTest.HashSize())
	commitSecret := make([]byte, suiteUnderTest.HashSize())
	for _, buf := range [][]byte{initSecret, commitSecret} {
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
	}

	pskSecret, err := schedule.PSKSecret(nil, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := schedule.KeySchedule(initSecret, commitSecret, pskSecret, context, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	return fixture{
		epoch: &Epoch{
			Number: 0, Suite: suiteUnderTest, Tree: ratchet, Context: context,
			Secrets: secrets, Transcript: messages.NewTranscript(),
			Proposals: messages.NewProposalCache(suiteUnderTest),
		},
		commitSec: commitSecret,
		bLeafPriv: bLeafPriv,
	}
}

func TestSenderAndReceiverAgreeOnTheNewEpoch(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")

	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

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

	// The sender's commit must carry a path: a self-update without one would leave the epoch
	// keys unchanged and provide no forward secrecy at all.
	if created.Content.Commit.Path == nil {
		t.Fatal("a self-update commit carries no update path")
	}
	if len(created.Content.Commit.Path.Nodes) == 0 {
		t.Fatal("the update path has no nodes")
	}
	if len(created.ConfirmationTag) == 0 {
		t.Fatal("the commit carries no confirmation tag")
	}

	// The receiver opens its path secret with its own private key. This is the HPKE path
	// running for real, not a callback that always answers yes.
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
		secret, err := crypto.DecryptWithLabel(f.bLeafPriv, "UpdatePathNode", contextBytes,
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		if err != nil {
			return nil, false
		}
		opened++
		return secret, true
	}

	next, err := f.epoch.ProcessCommit(created.AsInput([]byte(aPublic), nil, bApplier, originalHashes, nil))
	if err != nil {
		t.Fatalf("the receiver rejected a commit the sender built: %v", err)
	}

	if opened == 0 {
		t.Fatal("the receiver never opened a path secret, so the HPKE delivery was not exercised")
	}
	if next.Number != 1 {
		t.Fatalf("the commit opened epoch %d, want 1", next.Number)
	}

	// The sender's own epoch and the receiver's must be the same epoch, byte for byte.
	if !bytes.Equal(next.Context.TreeHash, created.Next.Context.TreeHash) {
		t.Fatal("the two sides disagree about the new tree hash")
	}
	if !bytes.Equal(next.Context.ConfirmedTranscriptHash, created.Next.Context.ConfirmedTranscriptHash) {
		t.Fatal("the two sides disagree about the confirmed transcript hash")
	}
	if !bytes.Equal(next.Transcript.Interim, created.Next.Transcript.Interim) {
		t.Fatal("the two sides disagree about the interim transcript hash")
	}

	for name, pair := range map[string][2][]byte{
		"encryption secret":   {next.Secrets.EncryptionSecret, created.Next.Secrets.EncryptionSecret},
		"confirmation key":    {next.Secrets.ConfirmationKey, created.Next.Secrets.ConfirmationKey},
		"init secret":         {next.Secrets.InitSecret, created.Next.Secrets.InitSecret},
		"membership key":      {next.Secrets.MembershipKey, created.Next.Secrets.MembershipKey},
		"epoch authenticator": {next.Secrets.EpochAuthenticator, created.Next.Secrets.EpochAuthenticator},
		"sender data secret":  {next.Secrets.SenderDataSecret, created.Next.Secrets.SenderDataSecret},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("the two sides derived different %s values", name)
		}
	}

	// The sender's new leaf key is in the tree on both sides.
	n := 2 * uint32(0)
	if !bytes.Equal(next.Tree[n].Leaf.EncryptionKey, created.Next.Tree[n].Leaf.EncryptionKey) {
		t.Fatal("the two sides disagree about the sender's new leaf key")
	}
}

func TestReceiverWithoutTheRightKeyCannotFollowTheCommit(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")
	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

	created, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		NewLeafNode: &tree.LeafNode{
			EncryptionKey: newLeafPub, SignatureKey: aPublic,
			Credential:   tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
			Capabilities: tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:       tree.LeafNodeSourceUpdate,
		},
		PathSecret: pathSecret,
	})
	if err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}

	originalHashes, err := tree.TreeHashes(f.epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	// An applier that can open nothing: the member does not hold the key for any node in the
	// copath resolution, which is exactly the position a member removed in an earlier commit
	// would be in.
	nothingApplier := func(uint32, tree.HPKECiphertext) ([]byte, bool) { return nil, false }

	if _, err := f.epoch.ProcessCommit(created.AsInput([]byte(aPublic), nil,
		nothingApplier, originalHashes, nil)); err == nil {
		t.Fatal("a member that could open no path secret still advanced to the new epoch, so " +
			"the epoch keys are not actually gated on the path")
	}

	// A wrong confirmation tag must be refused even when the path applies cleanly.
	forged := created.AsInput([]byte(aPublic), nil, nothingApplier, originalHashes, nil)
	forged.ConfirmationTag = bytes.Repeat([]byte{0x00}, len(created.ConfirmationTag))

	// Give it a working applier so the path succeeds and the tag check is what fails.
	contextBytes, err := f.epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	workingApplier := func(_ uint32, ct tree.HPKECiphertext) ([]byte, bool) {
		secret, err := crypto.DecryptWithLabel(f.bLeafPriv, "UpdatePathNode", contextBytes,
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		return secret, err == nil
	}
	forged.Applier = workingApplier

	if _, err := f.epoch.ProcessCommit(forged); err == nil {
		t.Fatal("a commit with a forged confirmation tag was accepted")
	}
}
