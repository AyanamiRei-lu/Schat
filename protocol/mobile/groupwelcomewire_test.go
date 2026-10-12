package mobile

import (
	"bytes"
	"testing"
)

// Group welcomes on the relay, and the one thing that must not happen: a welcome and a group
// message being mistaken for each other.
//
// They arrive by different routes — a welcome at the joiner's identity mailbox, a message at the
// group's — and are handled by different code, one of which PRODUCES the key the other uses. A
// mix-up is therefore not a decoding inconvenience; it is a client trying to open a group it is
// not in, or to join one it already is.

func TestGroupWelcomeEnvelopeRoundTrip(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	welcome := []byte("an MLS Welcome")

	wire, err := WrapGroupWelcome(token, welcome)
	if err != nil {
		t.Fatalf("WrapGroupWelcome: %v", err)
	}
	if wire[16] != ContentTypeGroupWelcome {
		t.Fatalf("the content type is %#02x, want %#02x", wire[16], ContentTypeGroupWelcome)
	}
	if !bytes.Equal(wire[:16], mustHexBytes(t, token)) {
		t.Fatal("the token did not survive, so the welcome would be routed to the wrong mailbox")
	}

	payload, err := UnwrapGroupWelcome(wire)
	if err != nil {
		t.Fatalf("UnwrapGroupWelcome: %v", err)
	}
	if !bytes.Equal(payload, welcome) {
		t.Fatalf("the welcome came back as %q", payload)
	}
}

func TestWelcomeAndMessageAreNotInterchangeable(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	payload := []byte("payload")

	// A group message must not be readable as a welcome...
	message := append(mustHexBytes(t, token), ContentTypeGroup)
	message = append(message, payload...)
	if _, err := UnwrapGroupWelcome(message); err == nil {
		t.Fatal("a group message was accepted as a welcome, so a client would try to join a " +
			"group it is already in")
	}

	// ...and a welcome must not be readable as a group message.
	welcome := append(mustHexBytes(t, token), ContentTypeGroupWelcome)
	welcome = append(welcome, payload...)
	if _, err := UnwrapGroup(welcome); err == nil {
		t.Fatal("a welcome was accepted as a group message, so a client would look for a group " +
			"it does not have")
	}

	// The one-to-one types must be refused by both, for the same reason.
	for _, kind := range []byte{0x01, 0x02} {
		wire := append(mustHexBytes(t, token), kind)
		wire = append(wire, payload...)
		if _, err := UnwrapGroupWelcome(wire); err == nil {
			t.Fatalf("content type %#02x was accepted as a welcome", kind)
		}
		if _, err := UnwrapGroup(wire); err == nil {
			t.Fatalf("content type %#02x was accepted as a group message", kind)
		}
	}
}

func TestGroupWelcomeEnvelopeRejectsBadInput(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"

	if _, err := WrapGroupWelcome("zz", []byte("welcome")); err == nil {
		t.Fatal("a non-hex token was accepted")
	}
	if _, err := WrapGroupWelcome(token, nil); err == nil {
		t.Fatal("an empty welcome was accepted")
	}
	// A type with nothing after it.
	empty := append(mustHexBytes(t, token), ContentTypeGroupWelcome)
	if _, err := UnwrapGroupWelcome(empty); err == nil {
		t.Fatal("an envelope with a type and no payload was accepted")
	}
	if _, err := UnwrapGroupWelcome([]byte("short")); err == nil {
		t.Fatal("a truncated envelope was accepted")
	}
}
