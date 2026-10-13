package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Whether a commit that CARRIES SOMETHING survives the wire.
//
// The earlier round-trip check used a self-update: an empty proposal list and nothing but a path.
// That is the simplest commit there is, and it passed — which is why the codec looked fine. The
// commit that fails in practice is an Add, whose proposals are a tagged union containing a whole
// nested KeyPackage. None of that had ever been round-tripped.
//
// A receiver hashes the bytes it parsed. If those differ from the bytes the sender signed, the
// two compute different confirmation tags from identical keys — and the failure appears at the
// tag, not at the parse, which is exactly what is being chased.

func TestACommitCarryingAnAddSurvivesTheWire(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")
	keyPackage, _ := memberCKeyPackage(t)

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
		t.Fatalf("the Add commit could not be created: %v", err)
	}

	authenticated := messages.AuthenticatedContent{
		WireFormat: created.WireFormat,
		Content:    *created.Content,
		Auth: messages.FramedContentAuthData{
			Signature:       created.Signature,
			ConfirmationTag: created.ConfirmationTag,
		},
	}

	w := mlstls.NewWriter(2048)
	if err := authenticated.Marshal(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}
	sent := w.Bytes()

	parsed, err := messages.ParseAuthenticatedContent(mlstls.NewReader(sent))
	if err != nil {
		t.Fatalf("the receiver cannot parse an Add commit at all: %v", err)
	}

	again := mlstls.NewWriter(2048)
	if err := parsed.Marshal(again); err != nil {
		t.Fatal(err)
	}
	if err := again.Err(); err != nil {
		t.Fatal(err)
	}
	reparsed := again.Bytes()

	if !bytes.Equal(sent, reparsed) {
		t.Fatalf("an Add commit does NOT survive the wire byte for byte.\n  sent     = %x\n  reparsed = %x\n"+
			"The receiver hashes different bytes than the sender signed, so the two compute "+
			"different confirmation tags from the same keys.", sent, reparsed)
	}

	// The proposal must be intact, not merely re-encodable.
	if parsed.Content.Commit == nil || len(parsed.Content.Commit.Proposals) != 1 {
		t.Fatal("the proposal list did not survive the round trip")
	}
	entry := parsed.Content.Commit.Proposals[0]
	if entry.Proposal == nil || entry.Proposal.Add == nil || entry.Proposal.Add.KeyPackage == nil {
		t.Fatal("the Add proposal did not survive the round trip")
	}
	if !bytes.Equal(entry.Proposal.Add.KeyPackage.LeafNode.EncryptionKey,
		keyPackage.LeafNode.EncryptionKey) {
		t.Fatal("the KeyPackage inside the proposal came back altered")
	}
}
