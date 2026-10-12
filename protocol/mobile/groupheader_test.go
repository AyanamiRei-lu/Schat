package mobile

import (
	"encoding/hex"
	"testing"
)

// A group message's public header: what a client reads to decide which group's state to reach
// for, before it can decrypt anything.

func TestGroupMessageHeaderNamesTheGroup(t *testing.T) {
	aliceIdentity, _, aliceState, bobState := membersInAGroup(t)

	sealed, err := GroupSeal(aliceState, aliceIdentity, hex.EncodeToString([]byte("header test")), 0)
	if err != nil {
		t.Fatalf("GroupSeal: %v", err)
	}

	header, err := GroupMessageHeader(sealed.MessageHex)
	if err != nil {
		t.Fatalf("GroupMessageHeader: %v", err)
	}

	summary, err := GroupStateSummary(bobState)
	if err != nil {
		t.Fatal(err)
	}
	if header.GroupIDHex != summary.GroupIDHex {
		t.Fatalf("the header names group %q and the state is in %q", header.GroupIDHex, summary.GroupIDHex)
	}
	if header.Epoch != summary.Epoch {
		t.Fatalf("the header says epoch %d and the state is in %d", header.Epoch, summary.Epoch)
	}
}

// TestTheHeaderIsReadableEvenWhenTheMessageIsBroken pins the distinction a client depends on: a
// message whose ciphertext was altered still PARSES, so the client can tell "this is for my
// group and it is damaged" from "this is not my group at all". Decryption is what proves the
// header was not tampered with, and that is exactly what fails.
func TestTheHeaderIsReadableEvenWhenTheMessageIsBroken(t *testing.T) {
	aliceIdentity, _, aliceState, bobState := membersInAGroup(t)

	sealed, err := GroupSeal(aliceState, aliceIdentity, hex.EncodeToString([]byte("tamper me")), 0)
	if err != nil {
		t.Fatal(err)
	}
	header, err := GroupMessageHeader(sealed.MessageHex)
	if err != nil {
		t.Fatal(err)
	}

	// Alter the last byte, which is inside the content ciphertext.
	raw, err := hex.DecodeString(sealed.MessageHex)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	broken := hex.EncodeToString(raw)

	afterHeader, err := GroupMessageHeader(broken)
	if err != nil {
		t.Fatalf("an altered message could not even be parsed, so a client could not tell a "+
			"damaged message from a foreign one: %v", err)
	}
	if afterHeader.GroupIDHex != header.GroupIDHex {
		t.Fatal("the group id changed, so it is not the plaintext field it is documented to be")
	}

	// And decryption must fail, because the header is bound into what the content ciphertext
	// authenticates.
	if _, err := GroupOpen(bobState, broken); err == nil {
		t.Fatal("a message with an altered ciphertext opened")
	}

	// The intact message still opens, so the above did not pass by accident.
	if _, err := GroupOpen(bobState, sealed.MessageHex); err != nil {
		t.Fatalf("the intact message did not open: %v", err)
	}
}

func TestGroupMessageHeaderRejectsGarbage(t *testing.T) {
	if _, err := GroupMessageHeader("not hex"); err == nil {
		t.Fatal("a non-hex message was accepted")
	}
	if _, err := GroupMessageHeader(""); err == nil {
		t.Fatal("an empty message was accepted")
	}
	if _, err := GroupMessageHeader("0011"); err == nil {
		t.Fatal("a truncated message was accepted")
	}
}
