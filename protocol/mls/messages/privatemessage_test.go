package messages

import (
	"bytes"
	"testing"

	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// The private message codec, plus the two differences that decide interoperability: the AADs
// are not the same construction, and the reuse guard is a fixed four bytes.

func TestPrivateMessageRoundTrip(t *testing.T) {
	original := &PrivateMessage{
		GroupID:             []byte("group-1"),
		Epoch:               7,
		ContentType:         ContentTypeApplication,
		AuthenticatedData:   []byte("ad"),
		EncryptedSenderData: bytes.Repeat([]byte{0x11}, 40),
		Ciphertext:          bytes.Repeat([]byte{0x22}, 96),
	}

	encoded, err := MarshalPrivateMessage(original)
	if err != nil {
		t.Fatalf("MarshalPrivateMessage: %v", err)
	}

	decoded, err := ParsePrivateMessage(mlstls.NewReader(encoded))
	if err != nil {
		t.Fatalf("decoding its own output: %v", err)
	}

	reencoded, err := MarshalPrivateMessage(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("the round trip changed the bytes")
	}

	if decoded.Epoch != original.Epoch || decoded.ContentType != original.ContentType {
		t.Fatal("the epoch or content type did not survive")
	}
	if !bytes.Equal(decoded.AuthenticatedData, original.AuthenticatedData) {
		t.Fatal("the authenticated data did not survive")
	}
	if !bytes.Equal(decoded.Ciphertext, original.Ciphertext) {
		t.Fatal("the ciphertext did not survive")
	}
}

func TestSenderDataRoundTripAndFixedGuard(t *testing.T) {
	original := &SenderData{LeafIndex: 3, Generation: 9}
	copy(original.ReuseGuard[:], []byte{0xAA, 0xBB, 0xCC, 0xDD})

	encoded, err := MarshalSenderData(original)
	if err != nil {
		t.Fatalf("MarshalSenderData: %v", err)
	}

	// Four bytes of guard, two uint32s: twelve bytes, no length prefixes anywhere.
	if len(encoded) != 12 {
		t.Fatalf("the sender data is %d bytes, want 12 — the reuse guard is a FIXED four-byte "+
			"field, and a length prefix would make it more", len(encoded))
	}

	decoded, err := ParseSenderData(mlstls.NewReader(encoded))
	if err != nil {
		t.Fatalf("decoding its own output: %v", err)
	}
	if decoded.LeafIndex != 3 || decoded.Generation != 9 {
		t.Fatalf("the sender data became leaf %d generation %d", decoded.LeafIndex, decoded.Generation)
	}
	if decoded.ReuseGuard != original.ReuseGuard {
		t.Fatal("the reuse guard did not survive")
	}
}

// TestTheTwoAADsAreNotTheSameConstruction is the check that stands in for a vector this layer
// does not have.
//
// The content's associated data includes authenticated_data; the sender data's does not. An
// implementation that used one for both would encrypt and decrypt against itself perfectly and
// fail against every other client — the exact class of defect that no local test catches.
func TestTheTwoAADsAreNotTheSameConstruction(t *testing.T) {
	groupID := []byte("group-1")
	epoch := uint64(7)
	authenticatedData := []byte("ad")

	contentAAD, err := PrivateContentAAD(groupID, epoch, ContentTypeApplication, authenticatedData)
	if err != nil {
		t.Fatal(err)
	}
	senderAAD, err := SenderDataAAD(groupID, epoch, ContentTypeApplication)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(contentAAD, senderAAD) {
		t.Fatal("the two AADs are identical, so authenticated_data is not being bound into the " +
			"content's associated data as the specification requires")
	}

	// The sender data's AAD must be exactly the three fields, with no authenticated_data: this
	// is what distinguishes it, and it is what a reader is most likely to assume away.
	want := mlstls.NewWriter(16)
	want.Opaque(groupID)
	want.Uint64(epoch)
	want.Uint8(uint8(ContentTypeApplication))
	if err := want.Err(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(senderAAD, want.Bytes()) {
		t.Fatalf("the sender data AAD is\n  %x\nwant\n  %x", senderAAD, want.Bytes())
	}

	// And the content's must carry the authenticated data, so changing it must change the AAD.
	otherAAD, err := PrivateContentAAD(groupID, epoch, ContentTypeApplication, []byte("ad!"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(contentAAD, otherAAD) {
		t.Fatal("changing authenticated_data did not change the content AAD, so it is not bound " +
			"into what the content ciphertext authenticates")
	}

	// The content type is bound into both, so a message cannot be re-presented as another kind.
	proposalAAD, err := PrivateContentAAD(groupID, epoch, ContentTypeProposal, authenticatedData)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(contentAAD, proposalAAD) {
		t.Fatal("the content type is not bound into the content AAD")
	}
}
