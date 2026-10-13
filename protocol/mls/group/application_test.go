package group

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/secrettree"
)

// Group messages: sealing and opening, and the four ways a message must be refused.

func stdAESSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func stdAESOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func applicationFixture(t *testing.T) (*secrettree.Tree, []byte, []byte) {
	t.Helper()

	encryptionSecret := make([]byte, suiteUnderTest.HashSize())
	for i := range encryptionSecret {
		encryptionSecret[i] = byte(i + 1)
	}

	tree, err := secrettree.New(encryptionSecret, 4, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	senderDataKey := bytes.Repeat([]byte{0x5A}, suiteUnderTest.HashSize())
	return tree, senderDataKey, nil
}

func TestApplicationMessageRoundTrip(t *testing.T) {
	tree, senderDataKey, _ := applicationFixture(t)
	groupID := []byte("group-1")

	ratchet, err := tree.ApplicationRatchet(1)
	if err != nil {
		t.Fatal(err)
	}

	senderData := messages.SenderData{LeafIndex: 1, Generation: 0}
	copy(senderData.ReuseGuard[:], []byte{0x11, 0x22, 0x33, 0x44})

	sealed, err := SealApplication(SealApplicationInput{
		GroupID:           groupID,
		Epoch:             3,
		AuthenticatedData: []byte("ad"),
		Ratchet:           ratchet,
		SenderData:        senderData,
		SenderDataSecret:  senderDataKey,
		Plaintext:         []byte("a message long enough for the sample"),
		Seal:              stdAESSeal,
		AdvanceRatchet:    true,
	})
	if err != nil {
		t.Fatalf("SealApplication: %v", err)
	}

	// The sender's ratchet moved, so the next message uses a different key.
	if ratchet.Generation != 1 {
		t.Fatalf("the sender's ratchet is at generation %d after one message, want 1", ratchet.Generation)
	}

	// A receiver builds its own ratchet for the same leaf, from the same epoch secret.
	receiverTree, _, _ := applicationFixture(t)
	opened, err := OpenApplication(OpenApplicationInput{
		Message:          sealed,
		ExpectedEpoch:    3,
		ExpectedGroupID:  groupID,
		Tree:             receiverTree,
		SenderDataSecret: senderDataKey,
		Open:             stdAESOpen,
	})
	if err != nil {
		t.Fatalf("OpenApplication: %v", err)
	}

	if string(opened.Plaintext) != "a message long enough for the sample" {
		t.Fatalf("the plaintext came back as %q", opened.Plaintext)
	}
	if opened.SenderData.LeafIndex != 1 || opened.SenderData.Generation != 0 {
		t.Fatalf("the sender data came back as leaf %d generation %d",
			opened.SenderData.LeafIndex, opened.SenderData.Generation)
	}
}

// TestApplicationMessagesAreRefusedWhenTheyMust covers the failures a group message layer has
// to catch. None of them produces a distinguishable error locally unless the code checks, which
// is why each is asserted rather than assumed.
func TestApplicationMessagesAreRefusedWhenTheyMust(t *testing.T) {
	tree, senderDataKey, _ := applicationFixture(t)
	groupID := []byte("group-1")

	seal := func(generation uint32, guard byte, plaintext string) *messages.PrivateMessage {
		ratchet, err := tree.ApplicationRatchet(1)
		if err != nil {
			t.Fatal(err)
		}
		senderData := messages.SenderData{LeafIndex: 1, Generation: generation}
		for i := range senderData.ReuseGuard {
			senderData.ReuseGuard[i] = guard
		}
		sealed, err := SealApplication(SealApplicationInput{
			GroupID: groupID, Epoch: 3,
			AuthenticatedData: []byte("ad"),
			Ratchet:           ratchet, SenderData: senderData,
			SenderDataSecret: senderDataKey,
			Plaintext:        []byte(plaintext), Seal: stdAESSeal,
		})
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}

	open := func(msg *messages.PrivateMessage) error {
		_, err := OpenApplication(OpenApplicationInput{
			Message: msg, ExpectedEpoch: 3, ExpectedGroupID: groupID,
			Tree: tree, SenderDataSecret: senderDataKey,
			Open: stdAESOpen,
		})
		return err
	}

	// A correct message opens, so the negatives below are not passing on a broken baseline.
	good := seal(0, 0x01, "a message long enough for the sample")
	if err := open(good); err != nil {
		t.Fatalf("a correct message did not open: %v", err)
	}

	// A flipped bit in the content.
	tampered := *good
	tampered.Ciphertext = append([]byte(nil), good.Ciphertext...)
	tampered.Ciphertext[0] ^= 0x01
	if err := open(&tampered); err == nil {
		t.Fatal("a message with a flipped ciphertext bit opened")
	}

	// A changed authenticated_data: it is bound into the content AAD, so the content must fail.
	changedAD := *good
	changedAD.AuthenticatedData = []byte("ad!")
	if err := open(&changedAD); err == nil {
		t.Fatal("changing authenticated_data did not invalidate the message, so it is not bound " +
			"into what the ciphertext authenticates")
	}

	// Another epoch: refused before any decryption is attempted.
	wrongEpoch := *good
	wrongEpoch.Epoch = 4
	if err := open(&wrongEpoch); err == nil {
		t.Fatal("a message from another epoch was accepted")
	}

	// Another group.
	wrongGroup := *good
	wrongGroup.GroupID = []byte("group-2")
	if err := open(&wrongGroup); err == nil {
		t.Fatal("a message from another group was accepted")
	}

	// A tampered sender data: the leaf index it names cannot be trusted, so this must fail
	// before the content is touched.
	tamperedSender := *good
	tamperedSender.EncryptedSenderData = append([]byte(nil), good.EncryptedSenderData...)
	tamperedSender.EncryptedSenderData[0] ^= 0x01
	if err := open(&tamperedSender); err == nil {
		t.Fatal("a message with tampered sender data opened")
	}
}

// TestTheReuseGuardChangesTheNonce pins the one transformation that keeps two messages under the
// same generation from sharing a nonce. Without it an AEAD key would be used twice with the
// same nonce, which is the single failure mode an AEAD does not survive — and it would be
// invisible here, because both messages would still open.
func TestTheReuseGuardChangesTheNonce(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x00}, suiteUnderTest.AEADNonceSize())

	var guardA, guardB [messages.ReuseGuardSize]byte
	copy(guardA[:], []byte{0x01, 0x02, 0x03, 0x04})
	copy(guardB[:], []byte{0x05, 0x06, 0x07, 0x08})

	a := applyReuseGuard(nonce, guardA)
	b := applyReuseGuard(nonce, guardB)

	if bytes.Equal(a, b) {
		t.Fatal("two different reuse guards produced the same nonce, so the guard is not being " +
			"mixed in")
	}
	if bytes.Equal(a, nonce) {
		t.Fatal("the guard did not change the nonce at all")
	}

	// Only the first four bytes are touched: the rest is the ratchet's own nonce, and using a
	// longer guard would consume part of it.
	for i := messages.ReuseGuardSize; i < len(nonce); i++ {
		if a[i] != nonce[i] {
			t.Fatalf("the guard changed byte %d of the nonce, beyond the four it owns", i)
		}
	}
	if !bytes.Equal(a[:4], guardA[:]) {
		t.Fatalf("the guard did not XOR into the first four bytes: %x", a[:4])
	}
}
