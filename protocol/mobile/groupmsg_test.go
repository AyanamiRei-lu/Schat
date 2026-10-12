package mobile

import (
	"encoding/hex"
	"testing"
)

// A message, end to end, across the binding.
//
// The add-and-join path was already proven; this is the other half — that the two members who
// agreed on an epoch can actually exchange something in it. The pieces were each verified: the
// ratchet against 656 official values, the sender data keys against 12 more, the sealing against
// its own negatives. What none of that checked is whether the binding hands each of them what it
// needs, in an order that exists in the real world.

// membersInAGroup builds a two-member group and returns both states.
func membersInAGroup(t *testing.T) (aliceIdentity, bobIdentity, aliceState, bobState string) {
	t.Helper()

	aliceIdentity = testIdentityJSON(t)
	bobIdentity = testIdentityJSON(t)

	created, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}

	bobKeyPackage, err := GroupKeyPackage(bobIdentity)
	if err != nil {
		t.Fatalf("GroupKeyPackage: %v", err)
	}

	added, err := GroupAddMember(created, aliceIdentity, bobKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("GroupAddMember: %v", err)
	}

	bobState, err = GroupProcessWelcome(added.WelcomeHex, bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex)
	if err != nil {
		t.Fatalf("GroupProcessWelcome: %v", err)
	}

	return aliceIdentity, bobIdentity, added.StateJSON, bobState
}

func TestGroupMessageRoundTripAcrossTheBinding(t *testing.T) {
	aliceIdentity, _, aliceState, bobState := membersInAGroup(t)

	// Short on purpose: five bytes is well under the length the AEAD needs to sample from, so
	// this exercises the framing as well as the sealing.
	sealed, err := GroupSeal(aliceState, aliceIdentity, hex.EncodeToString([]byte("hello")), 0)
	if err != nil {
		t.Fatalf("GroupSeal: %v", err)
	}
	if sealed.MessageHex == "" {
		t.Fatal("sealing produced no message")
	}
	if sealed.NextGeneration != 1 {
		t.Fatalf("the ratchet advanced to generation %d, want 1", sealed.NextGeneration)
	}

	opened, err := GroupOpen(bobState, sealed.MessageHex)
	if err != nil {
		t.Fatalf("Bob could not read Alice's message: %v", err)
	}

	plaintext, err := hex.DecodeString(opened.PlaintextHex)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "hello" {
		t.Fatalf("Bob read %q, want %q — the framing must be reversible byte for byte, "+
			"including a payload shorter than the padding floor", plaintext, "hello")
	}
	if opened.SenderLeaf != 0 {
		t.Fatalf("Bob attributes the message to leaf %d; Alice is leaf 0", opened.SenderLeaf)
	}
	if opened.Generation != 0 {
		t.Fatalf("the message came from generation %d, want 0", opened.Generation)
	}

	// A second message must use the next generation, and must also be readable: a sender that
	// failed to advance would reuse a key, and a receiver that could not follow would fail here.
	second, err := GroupSeal(aliceState, aliceIdentity,
		hex.EncodeToString([]byte("a second message")), sealed.NextGeneration)
	if err != nil {
		t.Fatalf("the second message could not be sealed: %v", err)
	}
	if second.MessageHex == sealed.MessageHex {
		t.Fatal("two messages produced identical bytes, so the ratchet did not advance")
	}

	secondOpened, err := GroupOpen(bobState, second.MessageHex)
	if err != nil {
		t.Fatalf("Bob could not read the second message: %v", err)
	}
	secondText, err := hex.DecodeString(secondOpened.PlaintextHex)
	if err != nil {
		t.Fatal(err)
	}
	if string(secondText) != "a second message" {
		t.Fatalf("the second message read back as %q", secondText)
	}
}

// TestAnOutsiderCannotReadAGroupMessage is the negative that says the messages are protected
// rather than merely encoded.
//
// The outsider is a fully valid member — of a DIFFERENT group. It holds a real epoch secret, a
// real ratchet and a real implementation of everything; the only thing it lacks is this group's
// secret. That is a stronger check than handing the message to something that cannot parse it.
func TestAnOutsiderCannotReadAGroupMessage(t *testing.T) {
	aliceIdentity, _, aliceState, bobState := membersInAGroup(t)

	sealed, err := GroupSeal(aliceState, aliceIdentity, hex.EncodeToString([]byte("for Bob only")), 0)
	if err != nil {
		t.Fatal(err)
	}

	// A different group, with a different secret, belonging to somebody else.
	carolIdentity := testIdentityJSON(t)
	carolState, err := GroupCreate(carolIdentity, "67727039")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GroupOpen(carolState, sealed.MessageHex); err == nil {
		t.Fatal("a member of another group read the message, so it is not bound to this group's " +
			"secret")
	}

	// A flipped bit must not open.
	for _, at := range []int{0, 10, 40} {
		tampered := []byte(sealed.MessageHex)
		// Flip one hex digit, which is one nibble of one byte.
		if tampered[at] == '0' {
			tampered[at] = '1'
		} else {
			tampered[at] = '0'
		}
		if _, err := GroupOpen(bobState, string(tampered)); err == nil {
			t.Fatalf("a message with a flipped nibble at position %d opened", at)
		}
	}

	// The intended recipient still reads it, so none of the above passed by accident.
	if _, err := GroupOpen(bobState, sealed.MessageHex); err != nil {
		t.Fatalf("the intended recipient could not read the message: %v", err)
	}
}
