package mobile

import (
	"bytes"
	"testing"
)

// Nickname announcements on the relay.
//
// They use two envelope types (0x06 one-to-one, 0x07 group) because the receiver must know
// WHICH machinery to reach for before it tries: an SCS-1 frame and an MLS private message
// are protected by different keys and a mix-up would surface as a decryption error rather
// than as "this is not yours".

func TestGroupProfileEnvelopeRoundTrips(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	message := []byte("SCHAT-NICK-1\nQQ==")

	wire, err := WrapGroupProfile(token, message)
	if err != nil {
		t.Fatalf("WrapGroupProfile: %v", err)
	}
	if len(wire) != 17+len(message) {
		t.Fatalf("the envelope is %d bytes; a token, a type and the payload make %d",
			len(wire), 17+len(message))
	}
	if wire[16] != ContentTypeGroupProfile {
		t.Fatalf("the content type is %#02x, want %#02x", wire[16], ContentTypeGroupProfile)
	}
	if !bytes.Equal(wire[:16], mustHexBytes(t, token)) {
		t.Fatal("the token did not come through unchanged")
	}

	payload, err := UnwrapGroupProfile(wire)
	if err != nil {
		t.Fatalf("UnwrapGroupProfile: %v", err)
	}
	if !bytes.Equal(payload, message) {
		t.Fatalf("the payload came back as %q", payload)
	}
}

func TestUnwrapGroupProfileRefusesOtherTypes(t *testing.T) {
	token := mustHexBytes(t, "00112233445566778899aabbccddeeff")

	for _, kind := range []byte{
		ContentTypeFrame,
		ContentTypeHandshake,
		ContentTypeGroup,
		ContentTypeGroupWelcome,
		ContentTypeGroupCommit,
		ContentTypeProfile,
	} {
		wire := append(append([]byte{}, token...), kind)
		wire = append(wire, []byte("payload")...)
		if _, err := UnwrapGroupProfile(wire); err == nil {
			t.Fatalf("an envelope of type %#02x was accepted as a group nickname announcement", kind)
		}
	}
}

func TestUnwrapGroupRefusesAGroupProfile(t *testing.T) {
	// The other direction matters just as much: a group nickname announcement must not be
	// handed to the MLS message path, where it would fail as a decryption error.
	token := mustHexBytes(t, "00112233445566778899aabbccddeeff")
	wire := append(append([]byte{}, token...), ContentTypeGroupProfile)
	wire = append(wire, []byte("SCHAT-NICK-1\nQQ==")...)

	if _, err := UnwrapGroup(wire); err == nil {
		t.Fatal("a group nickname announcement was accepted as a group message")
	}
}

func TestWrapGroupProfileRejectsBadInput(t *testing.T) {
	if _, err := WrapGroupProfile("not-hex", []byte("payload")); err == nil {
		t.Fatal("a non-hex token was accepted")
	}
	if _, err := WrapGroupProfile("00112233", []byte("payload")); err == nil {
		t.Fatal("a token that is not 16 bytes was accepted")
	}
	if _, err := WrapGroupProfile("00112233445566778899aabbccddeeff", nil); err == nil {
		t.Fatal("an empty payload was accepted")
	}
}
