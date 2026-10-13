package group

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/secrettree"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// Sealing and opening application messages (RFC 9420 sections 6.3 and 9.1).
//
// A private message is protected in two layers, each with its own key and its own associated
// data:
//
//	sender data: AEAD.Seal(sender_data_key, sender_data_nonce, SenderData, SenderDataAAD)
//	content:     AEAD.Seal(ratchet_key, ratchet_nonce XOR reuse_guard, plaintext, PrivateContentAAD)
//
// # The three things that are easy to get wrong, and invisible when they are
//
//  1. The two AADs DIFFER: the content's includes authenticated_data and the sender data's does
//     not. One construction for both is self-consistent and agreed with by nobody.
//
//  2. The content nonce is the ratchet nonce with the reuse guard XORed into its first four
//     bytes. Without that, two messages under the same generation would share a nonce — the one
//     failure an AEAD cannot survive — and the guard is what lets a sender pick a fresh one.
//
//  3. The receiver must use the GENERATION NAMED IN THE MESSAGE, not its own ratchet position.
//     A receiver that used its own position would fail on every message that arrived out of
//     order, and would succeed on none that did not.
//
// # Where the AEAD lives
//
// The seal and open operations are supplied by the caller. This package holds no AEAD
// interface of its own, and inventing one here would mean guessing at the shape the crypto
// package will eventually settle on; passing two functions keeps that decision where it
// belongs and keeps this file checkable.

// AEADSealer seals a plaintext under a key and nonce with associated data.
type AEADSealer func(key, nonce, plaintext, associatedData []byte) ([]byte, error)

// AEADOpener opens a ciphertext under a key and nonce with associated data.
type AEADOpener func(key, nonce, ciphertext, associatedData []byte) ([]byte, error)

// SealApplicationInput is everything needed to protect one application message.
type SealApplicationInput struct {
	GroupID           []byte
	Epoch             uint64
	AuthenticatedData []byte

	// Ratchet is the SENDER's application ratchet, positioned at the generation to use.
	Ratchet *secrettree.Ratchet

	// SenderData describes the sender and carries a FRESH reuse guard. Reusing a guard with the
	// same generation would reuse the nonce, so the caller must draw it anew for every message.
	SenderData messages.SenderData

	// SenderDataSecret is the epoch's sender data secret. The key and nonce that protect the
	// sender data are derived from it AND from a sample of the content ciphertext — which does
	// not exist until the content below is sealed.
	//
	// That is why this field is the SECRET and not the key. An earlier version asked the caller
	// for the key, which no caller can produce: the sample comes from the very ciphertext this
	// function is about to create. The function was therefore unusable in the order the
	// specification requires, and its tests did not notice because they passed arbitrary
	// constants where a derivation belongs.
	SenderDataSecret []byte

	Plaintext []byte
	Seal      AEADSealer

	// AdvanceRatchet moves the sender's ratchet past the generation just used. A sender must
	// not reuse a generation, and section 9.2 requires the value to be deleted once consumed.
	AdvanceRatchet bool
}

// SealApplication protects one application message and returns it ready to send.
func SealApplication(in SealApplicationInput) (*messages.PrivateMessage, error) {
	if in.Ratchet == nil {
		return nil, fmt.Errorf("mls/group: no ratchet to seal with")
	}
	if in.Seal == nil {
		return nil, fmt.Errorf("mls/group: no AEAD sealer")
	}
	if len(in.SenderDataSecret) == 0 {
		return nil, fmt.Errorf("mls/group: the sender data needs the epoch's sender data secret")
	}

	contentAAD, err := messages.PrivateContentAAD(in.GroupID, in.Epoch,
		messages.ContentTypeApplication, in.AuthenticatedData)
	if err != nil {
		return nil, err
	}

	// The key comes from the generation the message will CLAIM, not from wherever the ratchet
	// happens to sit. Those are two places holding one fact, and when they disagreed the sender
	// sealed successfully while every receiver — which has only the claimed generation — failed
	// to open. One source of truth: what the sender data says.
	key, nonce, err := in.Ratchet.KeyNonceAt(in.SenderData.Generation)
	if err != nil {
		return nil, err
	}

	ciphertext, err := in.Seal(key, applyReuseGuard(nonce, in.SenderData.ReuseGuard),
		in.Plaintext, contentAAD)
	if err != nil {
		return nil, fmt.Errorf("mls/group: sealing the content: %w", err)
	}

	senderDataPlaintext, err := messages.MarshalSenderData(&in.SenderData)
	if err != nil {
		return nil, err
	}

	senderDataAAD, err := messages.SenderDataAAD(in.GroupID, in.Epoch, messages.ContentTypeApplication)
	if err != nil {
		return nil, err
	}

	// Now that the content is sealed, its ciphertext exists — and its first HashSize bytes are
	// the sample the sender data keys come from. The order is forced by the specification, so it
	// is enforced here rather than left to a caller that cannot satisfy it.
	senderDataKey, senderDataNonce, err := secrettree.SenderDataKeyNonce(in.SenderDataSecret,
		ciphertext, in.Ratchet.Suite)
	if err != nil {
		return nil, err
	}

	// Sealed with its own — different — AAD.
	encryptedSenderData, err := in.Seal(senderDataKey, senderDataNonce,
		senderDataPlaintext, senderDataAAD)
	if err != nil {
		return nil, fmt.Errorf("mls/group: sealing the sender data: %w", err)
	}

	if in.AdvanceRatchet {
		if err := in.Ratchet.Advance(); err != nil {
			return nil, err
		}
	}

	return &messages.PrivateMessage{
		GroupID:             in.GroupID,
		Epoch:               in.Epoch,
		ContentType:         messages.ContentTypeApplication,
		AuthenticatedData:   in.AuthenticatedData,
		EncryptedSenderData: encryptedSenderData,
		Ciphertext:          ciphertext,
	}, nil
}

// OpenApplicationInput is everything needed to read one application message.
type OpenApplicationInput struct {
	Message *messages.PrivateMessage

	// ExpectedEpoch and ExpectedGroupID are what the receiver believes it is in. A message from
	// another epoch or another group must be refused rather than attempted: its ratchet does not
	// exist here, and trying anyway turns a clear rejection into a decryption failure.
	ExpectedEpoch   uint64
	ExpectedGroupID []byte

	// Tree is the epoch's secret tree, from which the sender's ratchet is taken by leaf index.
	Tree *secrettree.Tree

	// SenderDataSecret derives the sender data keys, together with a sample of the message's own
	// ciphertext. On this side there is no ordering problem — the ciphertext arrived — but the
	// derivation is still done here so that both directions use one implementation of it.
	SenderDataSecret []byte

	Open AEADOpener
}

// OpenApplicationResult is the plaintext and what the message said about its sender.
type OpenApplicationResult struct {
	Plaintext  []byte
	SenderData messages.SenderData
}

// OpenApplication reads one application message.
//
// The sender's ratchet is built from the leaf index the message names, and positioned at the
// generation it names. Both come from the message, and both are what makes out-of-order
// delivery work; a receiver that used its own position would fail on any message that did not
// arrive in the order it was sent.
func OpenApplication(in OpenApplicationInput) (*OpenApplicationResult, error) {
	if in.Message == nil {
		return nil, fmt.Errorf("mls/group: no message")
	}
	if in.Open == nil {
		return nil, fmt.Errorf("mls/group: no AEAD opener")
	}
	if in.Tree == nil {
		return nil, fmt.Errorf("mls/group: no secret tree")
	}
	if in.Message.ContentType != messages.ContentTypeApplication {
		return nil, fmt.Errorf("mls/group: content type %d is not an application message",
			in.Message.ContentType)
	}
	if in.Message.Epoch != in.ExpectedEpoch {
		return nil, fmt.Errorf("mls/group: the message is for epoch %d and this member is in %d",
			in.Message.Epoch, in.ExpectedEpoch)
	}
	if len(in.ExpectedGroupID) > 0 && string(in.Message.GroupID) != string(in.ExpectedGroupID) {
		return nil, fmt.Errorf("mls/group: the message is for another group")
	}

	// The sender data first: it names the sender and the generation, and without them there is
	// no ratchet to look in. Its AAD excludes authenticated_data — the difference from the
	// content's AAD, and the reason the two are built by separate functions.
	senderDataAAD, err := messages.SenderDataAAD(in.Message.GroupID, in.Message.Epoch,
		in.Message.ContentType)
	if err != nil {
		return nil, err
	}

	senderDataKey, senderDataNonce, err := secrettree.SenderDataKeyNonce(in.SenderDataSecret,
		in.Message.Ciphertext, in.Tree.Suite)
	if err != nil {
		return nil, err
	}

	senderDataPlaintext, err := in.Open(senderDataKey, senderDataNonce,
		in.Message.EncryptedSenderData, senderDataAAD)
	if err != nil {
		return nil, fmt.Errorf("mls/group: opening the sender data: %w", err)
	}

	senderData, err := messages.ParseSenderData(mlstls.NewReader(senderDataPlaintext))
	if err != nil {
		return nil, err
	}

	// Now the sender's ratchet, at the generation the message names.
	ratchet, err := in.Tree.ApplicationRatchet(senderData.LeafIndex)
	if err != nil {
		return nil, err
	}
	key, nonce, err := ratchet.KeyNonceAt(senderData.Generation)
	if err != nil {
		return nil, err
	}

	contentAAD, err := messages.PrivateContentAAD(in.Message.GroupID, in.Message.Epoch,
		in.Message.ContentType, in.Message.AuthenticatedData)
	if err != nil {
		return nil, err
	}

	plaintext, err := in.Open(key, applyReuseGuard(nonce, senderData.ReuseGuard),
		in.Message.Ciphertext, contentAAD)
	if err != nil {
		return nil, fmt.Errorf("mls/group: opening the content: %w", err)
	}

	return &OpenApplicationResult{Plaintext: plaintext, SenderData: *senderData}, nil
}

// applyReuseGuard XORs the guard into the first four bytes of the nonce.
//
// The guard is drawn fresh for every message, which is what keeps two messages under the same
// generation from sharing a nonce. The rest of the nonce is the ratchet's own, so the result is
// unique per (ratchet, generation, guard) — and a caller that reused a guard would silently
// undo the whole point.
func applyReuseGuard(nonce []byte, guard [messages.ReuseGuardSize]byte) []byte {
	out := make([]byte, len(nonce))
	copy(out, nonce)

	for i := 0; i < messages.ReuseGuardSize && i < len(out); i++ {
		out[i] ^= guard[i]
	}
	return out
}
