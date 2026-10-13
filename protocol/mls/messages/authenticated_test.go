package messages

import (
	"bytes"
	"testing"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// TestAuthenticatedContentCannotBeReadWithTheWrongType is the test the low-level API could not
// pass, and the reason the safe entry point exists.
//
// The hazard: FramedContentAuthData's shape depends on the content type, and the type is not
// in those bytes. Parsing a commit's auth data as an application's therefore succeeds while
// leaving the confirmation tag unread — silently skipping the MAC that proves epoch
// agreement. The low-level function cannot detect this by construction, so callers must not
// be given the chance to make the mistake.
func TestAuthenticatedContentCannotBeReadWithTheWrongType(t *testing.T) {
	original := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content: FramedContent{
			GroupID: []byte("group"),
			Epoch:   9,
			Sender:  Sender{Type: SenderTypeMember, LeafIndex: 1},
			Type:    ContentTypeCommit,
			Commit: &Commit{Proposals: []*ProposalOrRef{
				{Type: ProposalOrRefTypeProposal, Proposal: sampleProposal(t, ProposalTypeRemove)},
			}},
		},
		Auth: FramedContentAuthData{
			Signature:       bytes.Repeat([]byte{0x5A}, 64),
			ConfirmationTag: bytes.Repeat([]byte{0x6B}, 32),
		},
	}

	w := mlstls.NewWriter(512)
	if err := original.Marshal(w); err != nil {
		t.Fatalf("encoding: %v", err)
	}
	encoded := w.Bytes()

	reader := mlstls.NewReader(encoded)
	decoded, err := ParseAuthenticatedContent(reader)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}

	// The whole message must be consumed. This is the check the low-level path could not make:
	// if the confirmation tag had been skipped, bytes would remain.
	if !reader.Empty() {
		t.Fatal("bytes were left unread after parsing a complete authenticated content, " +
			"which means a field is being skipped silently")
	}

	if decoded.Content.Type != ContentTypeCommit {
		t.Fatalf("content type became %d", decoded.Content.Type)
	}
	if len(decoded.Auth.ConfirmationTag) == 0 {
		t.Fatal("the commit's confirmation tag was not read, so the MAC over the epoch's " +
			"confirmed transcript hash would never be checked")
	}
	if !bytes.Equal(decoded.Auth.ConfirmationTag, original.Auth.ConfirmationTag) {
		t.Fatal("the confirmation tag did not survive the round trip")
	}
	if decoded.WireFormat != original.WireFormat {
		t.Fatal("the wire format did not survive")
	}

	// And the low-level hazard is asserted rather than assumed, so that if a future change
	// makes the auth data self-delimiting this test says so instead of quietly passing.
	authOnly := mlstls.NewWriter(128)
	if err := original.Auth.Marshal(authOnly, ContentTypeCommit); err != nil {
		t.Fatal(err)
	}
	misread := mlstls.NewReader(authOnly.Bytes())
	if _, err := ParseFramedContentAuthData(misread, ContentTypeApplication); err != nil {
		t.Fatalf("the low-level parser now rejects a type mismatch (%v); if the auth data has "+
			"become self-delimiting, the warning in authenticated.go should be updated", err)
	}
	if misread.Empty() {
		t.Fatal("the low-level parser consumed the confirmation tag as an application's auth " +
			"data, which would mean the two layouts are no longer distinguishable")
	}
	t.Log("confirmed: the low-level parser cannot detect a type mismatch, which is why " +
		"ParseAuthenticatedContent takes the type from the content itself")
}

func TestAuthenticatedContentRoundTripForEveryContentType(t *testing.T) {
	cases := []struct {
		name    string
		content FramedContent
	}{
		{"application", FramedContent{
			GroupID: []byte("g"), Epoch: 1,
			Sender:          Sender{Type: SenderTypeMember, LeafIndex: 0},
			Type:            ContentTypeApplication,
			ApplicationData: []byte("hi"),
		}},
		{"proposal", FramedContent{
			GroupID: []byte("g"), Epoch: 1,
			Sender:   Sender{Type: SenderTypeMember, LeafIndex: 0},
			Type:     ContentTypeProposal,
			Proposal: sampleProposal(t, ProposalTypeUpdate),
		}},
		{"commit", FramedContent{
			GroupID: []byte("g"), Epoch: 1,
			Sender: Sender{Type: SenderTypeMember, LeafIndex: 0},
			Type:   ContentTypeCommit,
			Commit: &Commit{Proposals: []*ProposalOrRef{
				{Type: ProposalOrRefTypeReference, Reference: bytes.Repeat([]byte{0x01}, 32)},
			}, Path: &tree.UpdatePath{LeafNode: sampleLeafNode(), Nodes: []tree.UpdatePathNode{}}},
		}},
	}

	for _, tc := range cases {
		original := &AuthenticatedContent{
			WireFormat: WireFormatPublicMessage,
			Content:    tc.content,
			Auth:       FramedContentAuthData{Signature: bytes.Repeat([]byte{0x77}, 64)},
		}
		if tc.content.Type == ContentTypeCommit {
			original.Auth.ConfirmationTag = bytes.Repeat([]byte{0x88}, 32)
		}

		w := mlstls.NewWriter(1024)
		if err := original.Marshal(w); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		reader := mlstls.NewReader(w.Bytes())
		decoded, err := ParseAuthenticatedContent(reader)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !reader.Empty() {
			t.Fatalf("%s: bytes were left unread after a complete parse", tc.name)
		}
		if decoded.Content.Type != tc.content.Type {
			t.Fatalf("%s: content type did not survive", tc.name)
		}

		// Re-encoding must reproduce the bytes exactly.
		w2 := mlstls.NewWriter(1024)
		if err := decoded.Marshal(w2); err != nil {
			t.Fatalf("%s: re-encoding: %v", tc.name, err)
		}
		if !bytes.Equal(w.Bytes(), w2.Bytes()) {
			t.Fatalf("%s: the round trip changed the bytes", tc.name)
		}
	}
}
