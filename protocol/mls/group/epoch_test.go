package group

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/schedule"
	"github.com/schat/schat/protocol/mls/tree"
)

// The first execution of the epoch transition.
//
// # Why this test performs the sender's derivation itself
//
// A sender has to compute the confirmation tag BEFORE sending, and the tag depends on the
// epoch the commit opens. There is no sender-side function yet 鈥?ProcessCommit only consumes
// a commit 鈥?so this test walks the sender's steps inline. That duplication is deliberate and
// temporary: it is the only way to execute ProcessCommit at all right now, and it doubles as
// an independent statement of what the sender must do. When a CreateCommit function exists,
// this test should be rewritten to call it, and the duplication removed. It is called out
// here rather than left for a reader to notice.

const suiteUnderTest = crypto.CipherSuite(0x0001)

func signerFor(label string) (ed25519.PrivateKey, []byte) {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, []byte(label))
	key := ed25519.NewKeyFromSeed(seed)
	return key, key.Public().(ed25519.PublicKey)
}

// twoMemberEpoch builds epoch 0 of a group with A at leaf 0 and B at leaf 1.
func twoMemberEpoch(t *testing.T) (*Epoch, []byte, []byte) {
	t.Helper()

	_, aPub := signerFor("member-a")
	_, bPub := signerFor("member-b")

	// Leaf encryption keys: the test holds no private halves because a commit that removes a
	// member carries no update path, so no path secret is ever opened.
	leafA := bytes.Repeat([]byte{0xA1}, 32)
	leafB := bytes.Repeat([]byte{0xB2}, 32)

	ratchet := make(tree.Tree, 3)
	ratchet[0] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: &tree.LeafNode{
		EncryptionKey: leafA, SignatureKey: aPub,
		Credential:   tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
		Capabilities: tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
		Source:       tree.LeafNodeSourceUpdate,
	}}
	ratchet[2] = &tree.Node{Type: tree.NodeTypeLeaf, Leaf: &tree.LeafNode{
		EncryptionKey: leafB, SignatureKey: bPub,
		Credential:   tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("B")},
		Capabilities: tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
		Source:       tree.LeafNodeSourceUpdate,
	}}
	ratchet[1] = &tree.Node{Type: tree.NodeTypeParent, Parent: &tree.ParentNode{
		EncryptionKey: bytes.Repeat([]byte{0xC3}, 32),
	}}

	initialTreeHash, err := treeHashOf(ratchet, suiteUnderTest)
	if err != nil {
		t.Fatalf("hashing the initial tree: %v", err)
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
	if _, err := rand.Read(initSecret); err != nil {
		t.Fatal(err)
	}
	commitSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(commitSecret); err != nil {
		t.Fatal(err)
	}

	pskSecret, err := schedule.PSKSecret(nil, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := schedule.KeySchedule(initSecret, commitSecret, pskSecret, context, suiteUnderTest)
	if err != nil {
		t.Fatalf("the initial key schedule: %v", err)
	}

	epoch := &Epoch{
		Number:     0,
		Suite:      suiteUnderTest,
		Tree:       ratchet,
		Context:    context,
		Secrets:    secrets,
		Transcript: messages.NewTranscript(),
		Proposals:  messages.NewProposalCache(suiteUnderTest),
	}
	return epoch, commitSecret, initSecret
}

// removeCommit builds, signs and tags a commit that removes leaf 1, performing the sender's
// derivation to obtain the confirmation tag.
func removeCommit(t *testing.T, epoch *Epoch, commitSecret []byte) (CommitInput, *Epoch) {
	// Section 12.4.1: this commit carries NO path, so its commit secret is the all-zero
	// vector of KDF.Nh. The helper used to compute the epoch keys from an arbitrary secret
	// while the content it built had no path — a combination that cannot occur, and which
	// made the sender and the receiver disagree the moment the receiver stopped being
	// handed the sender's secret.
	commitSecret = make([]byte, suiteUnderTest.HashSize())
	t.Helper()

	_, aPub := signerFor("member-a")
	aPrivate, _ := signerFor("member-a")
	_ = aPub

	content := &messages.FramedContent{
		GroupID: epoch.Context.GroupID,
		Epoch:   epoch.Number,
		Sender:  messages.Sender{Type: messages.SenderTypeMember, LeafIndex: 0},
		Type:    messages.ContentTypeCommit,
		Commit: &messages.Commit{Proposals: []*messages.ProposalOrRef{{
			Type:     messages.ProposalOrRefTypeProposal,
			Proposal: &messages.Proposal{Type: messages.ProposalTypeRemove, Remove: &messages.Remove{Removed: 1}},
		}}},
	}

	contextBytes, err := epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	signature, err := messages.SignFramedContent(messages.WireFormatPublicMessage, content,
		contextBytes, aPrivate, suiteUnderTest)
	if err != nil {
		t.Fatalf("signing the commit: %v", err)
	}

	// The sender's own derivation of the epoch it is opening.
	confirmedInput, err := messages.ConfirmedTranscriptHashInput(messages.WireFormatPublicMessage, content, signature)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := suiteUnderTest.Hash(concat(epoch.Transcript.Interim, confirmedInput))

	updated, err := epoch.applyProposalsAndPath(&CommitInput{Content: content}, nil)
	if err != nil {
		t.Fatalf("the sender could not apply its own commit: %v", err)
	}
	newTreeHash, err := treeHashOf(updated, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	nextContext := epoch.Context
	nextContext.Epoch = epoch.Number + 1
	nextContext.TreeHash = newTreeHash
	nextContext.ConfirmedTranscriptHash = confirmed

	pskSecret, err := schedule.PSKSecret(nil, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := schedule.KeySchedule(epoch.Secrets.InitSecret, commitSecret, pskSecret, nextContext, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := messages.ConfirmationTag(secrets.ConfirmationKey, confirmed, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	interimInput, err := messages.InterimTranscriptHashInput(tag)
	if err != nil {
		t.Fatal(err)
	}

	senderEpoch := &Epoch{
		Number:     epoch.Number + 1,
		Suite:      suiteUnderTest,
		Tree:       updated,
		Context:    nextContext,
		Secrets:    secrets,
		Transcript: messages.Transcript{Confirmed: confirmed, Interim: suiteUnderTest.Hash(concat(confirmed, interimInput))},
		Proposals:  messages.NewProposalCache(suiteUnderTest),
	}

	_, senderPub := signerFor("member-a")
	return CommitInput{
		WireFormat:         messages.WireFormatPublicMessage,
		Content:            content,
		Signature:          signature,
		ConfirmationTag:    tag,
		SenderSignatureKey: senderPub,
	}, senderEpoch
}

func TestProcessCommitOpensTheNextEpoch(t *testing.T) {
	epoch, commitSecret, _ := twoMemberEpoch(t)
	in, senderEpoch := removeCommit(t, epoch, commitSecret)

	next, err := epoch.ProcessCommit(in)
	if err != nil {
		t.Fatalf("ProcessCommit: %v", err)
	}

	if next.Number != 1 {
		t.Fatalf("the commit opened epoch %d, want 1", next.Number)
	}

	// The removed member's leaf is a hole, and the tree keeps its shape.
	if next.Tree[0] == nil {
		t.Fatal("the surviving member's leaf was removed")
	}
	if next.Tree[0] == nil {
		t.Fatal("the sender's own leaf was removed as well")
	}
	// The tree IS expected to change shape here. Removing the only member of the right subtree
	// leaves that half entirely blank, and the specification discards it: the root and the right
	// subtree go, and the surviving leaf becomes the root.
	//
	// The earlier version of this assertion required the shape to be KEPT, and it passed,
	// because both sides of this test run the same code. That is exactly how an interoperability
	// difference hides: self-consistent, green, and rejected by anybody else's client.
	if len(next.Tree) != 1 {
		t.Fatalf("after removing the only other member the tree has %d nodes, want 1 — the surviving member's leaf, which is now also the root", len(next.Tree))
	}
	if next.Tree[0] == nil || next.Tree[0].Leaf == nil {
		t.Fatal("the surviving member's leaf was lost in the truncation")
	}

	// Both sides must have derived the same epoch. This is the whole point of the
	// confirmation tag, and comparing the secrets directly is how a test can see it.
	if !bytes.Equal(next.Context.TreeHash, senderEpoch.Context.TreeHash) {
		t.Fatal("the two sides disagree about the new tree hash")
	}
	if !bytes.Equal(next.Context.ConfirmedTranscriptHash, senderEpoch.Context.ConfirmedTranscriptHash) {
		t.Fatal("the two sides disagree about the confirmed transcript hash")
	}
	for name, pair := range map[string][2][]byte{
		"epoch secret":        {next.Secrets.EncryptionSecret, senderEpoch.Secrets.EncryptionSecret},
		"confirmation key":    {next.Secrets.ConfirmationKey, senderEpoch.Secrets.ConfirmationKey},
		"init secret":         {next.Secrets.InitSecret, senderEpoch.Secrets.InitSecret},
		"membership key":      {next.Secrets.MembershipKey, senderEpoch.Secrets.MembershipKey},
		"epoch authenticator": {next.Secrets.EpochAuthenticator, senderEpoch.Secrets.EpochAuthenticator},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("the two sides derived different %s values", name)
		}
	}
	if !bytes.Equal(next.Transcript.Interim, senderEpoch.Transcript.Interim) {
		t.Fatal("the two sides disagree about the interim transcript hash")
	}

	// The receiver must not have been modified.
	if epoch.Number != 0 || len(epoch.Context.ConfirmedTranscriptHash) != 0 {
		t.Fatal("ProcessCommit modified the epoch it was called on")
	}
}

func TestProcessCommitRejectsAForgedOrStaleCommit(t *testing.T) {
	epoch, commitSecret, _ := twoMemberEpoch(t)

	// A wrong confirmation tag: the sender derived different group state, or an attacker
	// changed it. Nothing else distinguishes the two, and both must be refused.
	in, _ := removeCommit(t, epoch, commitSecret)
	forged := in
	forged.ConfirmationTag = bytes.Repeat([]byte{0x00}, len(in.ConfirmationTag))
	if _, err := epoch.ProcessCommit(forged); err == nil {
		t.Fatal("a commit with a wrong confirmation tag was accepted, so the sender's epoch was " +
			"never actually confirmed")
	}

	// No tag at all.
	in, _ = removeCommit(t, epoch, commitSecret)
	untagged := in
	untagged.ConfirmationTag = nil
	if _, err := epoch.ProcessCommit(untagged); err == nil {
		t.Fatal("a commit with no confirmation tag was accepted")
	}

	// A replayed commit: the content claims an epoch this member is not in.
	in, _ = removeCommit(t, epoch, commitSecret)
	replayed := in
	replayedContent := *in.Content
	replayedContent.Epoch = 5
	replayed.Content = &replayedContent
	if _, err := epoch.ProcessCommit(replayed); err == nil {
		t.Fatal("a commit for a future epoch was accepted")
	}

	// An altered proposal list must break the signature before anything is applied.
	in, _ = removeCommit(t, epoch, commitSecret)
	tampered := in
	tamperedContent := *in.Content
	tamperedCommit := *in.Content.Commit
	tamperedCommit.Proposals = []*messages.ProposalOrRef{{
		Type:     messages.ProposalOrRefTypeProposal,
		Proposal: &messages.Proposal{Type: messages.ProposalTypeRemove, Remove: &messages.Remove{Removed: 0}},
	}}
	tamperedContent.Commit = &tamperedCommit
	tampered.Content = &tamperedContent
	if _, err := epoch.ProcessCommit(tampered); err == nil {
		t.Fatal("a commit whose proposals were altered was accepted, so the signature does not " +
			"cover the proposal list")
	}

	// The wrong signing key.
	in, _ = removeCommit(t, epoch, commitSecret)
	_, otherPub := signerFor("member-b")
	wrongKey := in
	wrongKey.SenderSignatureKey = otherPub
	if _, err := epoch.ProcessCommit(wrongKey); err == nil {
		t.Fatal("a commit verified under another member's key")
	}

	// A proposal cited by reference and not resolved must be refused rather than skipped: a
	// commit that silently applied fewer proposals than it listed would leave two members in
	// different states.
	in, _ = removeCommit(t, epoch, commitSecret)
	byRef := in
	byRefContent := *in.Content
	byRefCommit := *in.Content.Commit
	byRefCommit.Proposals = []*messages.ProposalOrRef{{
		Type:      messages.ProposalOrRefTypeReference,
		Reference: bytes.Repeat([]byte{0x11}, 32),
	}}
	byRefContent.Commit = &byRefCommit
	byRef.Content = &byRefContent
	if _, err := epoch.ProcessCommit(byRef); err == nil {
		t.Fatal("an unresolved by-reference proposal was accepted")
	}
}
