package mobile

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Group frames on the relay.
//
// The property that matters is the one the server cannot check and the client must: an envelope
// says what it carries, and a group message is not mistaken for a one-to-one frame. The relay
// routes both the same way, so nothing upstream will catch a mix-up.

func TestGroupEnvelopeRoundTrip(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	message := []byte("an MLS private message")

	wire, err := WrapGroup(token, message)
	if err != nil {
		t.Fatalf("WrapGroup: %v", err)
	}

	if len(wire) != 17+len(message) {
		t.Fatalf("the envelope is %d bytes; a token, a type and the payload make %d",
			len(wire), 17+len(message))
	}
	if wire[16] != ContentTypeGroup {
		t.Fatalf("the content type is %#02x, want %#02x", wire[16], ContentTypeGroup)
	}
	if !bytes.Equal(wire[:16], mustHexBytes(t, token)) {
		t.Fatal("the token did not come through unchanged, so the message would be routed to the " +
			"wrong mailbox")
	}

	payload, err := UnwrapGroup(wire)
	if err != nil {
		t.Fatalf("UnwrapGroup: %v", err)
	}
	if !bytes.Equal(payload, message) {
		t.Fatalf("the payload came back as %q", payload)
	}
}

func TestGroupEnvelopeRefusesWhatItMust(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"

	// A one-to-one frame must not be read as a group message: the two are protected by
	// different machinery, and a caller that gets the wrong one needs to be told.
	frame := append(mustHexBytes(t, token), 0x01)
	frame = append(frame, []byte("some payload")...)
	if _, err := UnwrapGroup(frame); err == nil {
		t.Fatal("a one-to-one frame was accepted as a group message")
	}

	handshake := append(mustHexBytes(t, token), 0x02)
	handshake = append(handshake, []byte("some payload")...)
	if _, err := UnwrapGroup(handshake); err == nil {
		t.Fatal("a one-to-one handshake was accepted as a group message")
	}

	// A type with nothing after it.
	empty := append(mustHexBytes(t, token), ContentTypeGroup)
	if _, err := UnwrapGroup(empty); err == nil {
		t.Fatal("an envelope with a type and no payload was accepted")
	}

	// Too short to hold a token and a type at all.
	if _, err := UnwrapGroup([]byte("short")); err == nil {
		t.Fatal("a truncated envelope was accepted")
	}

	// An unknown type is refused rather than passed along: a payload this client cannot classify
	// is one it cannot protect itself against misreading.
	unknown := append(mustHexBytes(t, token), 0x7F)
	unknown = append(unknown, []byte("payload")...)
	if _, err := UnwrapGroup(unknown); err == nil {
		t.Fatal("an unknown content type was accepted")
	}
}

func TestWrapGroupRejectsBadInput(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"

	if _, err := WrapGroup("zz", []byte("payload")); err == nil {
		t.Fatal("a non-hex token was accepted")
	}
	// A token of the wrong length would be routed to a mailbox nobody is listening on, or worse,
	// to one belonging to somebody else.
	if _, err := WrapGroup("00112233", []byte("payload")); err == nil {
		t.Fatal("a short token was accepted")
	}
	if _, err := WrapGroup(token, nil); err == nil {
		t.Fatal("an empty message was accepted")
	}
}

func mustHexBytes(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
