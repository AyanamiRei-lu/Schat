package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Whether a commit survives the wire unchanged.
//
// The receiver's confirmation tag does not match, and the failure happens AFTER the path has been
// applied — so the member's keys are right and the tree is rebuilt. The tag is computed over the
// commit's own bytes, so if the bytes the receiver parses differ from the bytes the sender
// signed, the two compute different tags from identical keys.
//
// Nothing in this project had ever checked that: the KeyPackage codec was verified for round-trip
// stability, and the tree codecs have official vectors, but a COMMIT is only ever exercised in
// memory by the tests that create it.

func TestACommitSurvivesTheWireUnchanged(t *testing.T) {
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
		t.Fatal(err)
	}

	// Exactly what the binding sends: the framed content with its signature and confirmation tag.
	authenticated := messages.AuthenticatedContent{
		WireFormat: created.WireFormat,
		Content:    *created.Content,
		Auth: messages.FramedContentAuthData{
			Signature:       created.Signature,
			ConfirmationTag: created.ConfirmationTag,
		},
	}

	w := mlstls.NewWriter(1024)
	if err := authenticated.Marshal(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Err(); err != nil {
		t.Fatal(err)
	}
	onTheWire := w.Bytes()

	// What the receiver gets.
	parsed, err := messages.ParseAuthenticatedContent(mlstls.NewReader(onTheWire))
	if err != nil {
		t.Fatalf("the receiver cannot parse the commit at all: %v", err)
	}

	again := mlstls.NewWriter(1024)
	if err := parsed.Marshal(again); err != nil {
		t.Fatal(err)
	}
	if err := again.Err(); err != nil {
		t.Fatal(err)
	}
	afterParsing := again.Bytes()

	t.Logf("wire        = %x", onTheWire)
	t.Logf("after parse = %x", afterParsing)

	if !bytes.Equal(onTheWire, afterParsing) {
		t.Fatalf("a commit does NOT survive the wire byte for byte.\n  sent     = %x\n  reparsed = %x\n"+
			"The receiver hashes different bytes than the sender signed, so the two compute "+
			"different confirmation tags from the same keys — which is exactly the failure seen.",
			onTheWire, afterParsing)
	}

	// And the fields the receiver will actually hash must be the ones that were signed.
	if !bytes.Equal(parsed.Auth.Signature, created.Signature) {
		t.Fatal("the signature came back different")
	}
	if !bytes.Equal(parsed.Auth.ConfirmationTag, created.ConfirmationTag) {
		t.Fatal("the confirmation tag came back different")
	}
}
