package mobile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/group"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/secrettree"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// Sending and reading group messages, from the binding.
//
// # The length prefix, and why there is one
//
// MLS derives the sender data's key from the first KDF.Nh bytes of the content ciphertext, so a
// message whose ciphertext is shorter than KDF.Nh has no sample and cannot be sent at all. The
// AEAD tag is 16 bytes, so a plaintext under KDF.Nh-16 bytes — 16 bytes for the suite this build
// uses — would produce a ciphertext that is too short.
//
// Padding is therefore required, not optional. Rather than pad with something the receiver has
// to guess at, the payload is length-prefixed: four big-endian bytes of length, then the bytes
// themselves, then zeros to the minimum. A receiver reads the length and ignores the rest, so a
// payload that legitimately ends in zeros is not truncated — which padding without a length
// would do.
//
// # The generation, and why the caller keeps it
//
// A ratchet key must not be used twice. The group's snapshot does not carry the local sender's
// ratchet position, and adding it there would mean this package deciding a storage question that
// belongs to the client. The position is therefore passed in and returned: the caller stores it
// with the group state, and the seal call advances it.
//
// The reuse guard would keep two messages under one generation from sharing a nonce, so this is
// not the difference between working and broken — it is the difference between following
// section 9.2 and quietly ignoring it.
//
// # Padding is also a privacy measure
//
// A message that is padded to a fixed floor rather than sent at its natural length does not
// announce how short it was. That is the same reason the one-to-one frames are padded, and it is
// a side effect worth having rather than a cost to be minimised.

// groupPlaintextFloor is the smallest payload the AEAD can sample from.
//
// The sample is KDF.Nh bytes of ciphertext and the tag is 16 bytes, so the plaintext must be at
// least KDF.Nh-16 — and the four length bytes are part of the plaintext.
func groupPlaintextFloor(suite crypto.CipherSuite) int {
	const aeadTagSize = 16 // both AES-GCM and ChaCha20-Poly1305 use a 16-byte tag
	// The floor applies to the FRAMED payload — the four length bytes are part of what the AEAD
	// encrypts, so they do not reduce what is needed. Subtracting them as well produced a
	// ciphertext of 28 bytes for a short message: one byte short in the sample, and a failure
	// that names the AEAD rather than the arithmetic.
	floor := suite.HashSize() - aeadTagSize
	if floor < 0 {
		return 0
	}
	return floor
}

// frameGroupPayload length-prefixes a payload and pads it to the floor.
func frameGroupPayload(plaintext []byte, suite crypto.CipherSuite) []byte {
	framed := make([]byte, 4+len(plaintext))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(plaintext)))
	copy(framed[4:], plaintext)

	if len(framed) < groupPlaintextFloor(suite) {
		framed = append(framed, make([]byte, groupPlaintextFloor(suite)-len(framed))...)
	}
	return framed
}

// unframeGroupPayload reverses frameGroupPayload.
func unframeGroupPayload(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, fmt.Errorf("schat: the payload is too short to carry its own length")
	}
	length := binary.BigEndian.Uint32(padded[:4])
	if int(length) > len(padded)-4 {
		return nil, fmt.Errorf("schat: the payload says it is %d bytes and only %d followed",
			length, len(padded)-4)
	}
	return padded[4 : 4+length], nil
}

// GroupSealResult is the message and the ratchet position that follows it.
type GroupSealResult struct {
	// MessageHex is the private message to send. It travels in an envelope whose content type
	// marks it as a group frame, on the same relay connection as everything else.
	MessageHex string

	// NextGeneration is the value to pass to the next call of GroupSeal with this state. Sending
	// twice at the same generation is what it exists to prevent.
	NextGeneration int64
}

// GroupOpenResult is a decrypted message and what the sender claimed about itself.
type GroupOpenResult struct {
	PlaintextHex string

	// SenderLeaf is the leaf the message came from. It is authenticated by the epoch's ratchet
	// rather than asserted: the sender data that carries it is sealed under a key only a member
	// of this epoch can produce.
	SenderLeaf int

	// Generation is the sender's ratchet position for this message.
	Generation int64
}

// GroupSeal protects one application message for the group.
func GroupSeal(stateJSON, identityJSON, plaintextHex string, generation int64) (*GroupSealResult, error) {
	identity, err := IdentityFromJSON(identityJSON)
	if err != nil {
		return nil, err
	}
	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return nil, err
	}
	if generation < 0 || generation > int64(^uint32(0)) {
		return nil, fmt.Errorf("schat: generation %d is outside the range a message can carry", generation)
	}

	suite := crypto.CipherSuite(GroupCipherSuite)
	plaintext, err := hex.DecodeString(plaintextHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the plaintext is not hex: %w", err)
	}

	myLeaf, err := findMyLeaf(epoch, identity)
	if err != nil {
		return nil, err
	}

	leaves := uint32((len(epoch.Tree) + 1) / 2)
	secretTree, err := secrettree.New(epoch.Secrets.EncryptionSecret, leaves, suite)
	if err != nil {
		return nil, err
	}
	ratchet, err := secretTree.ApplicationRatchet(myLeaf)
	if err != nil {
		return nil, err
	}

	var guard [messages.ReuseGuardSize]byte
	if _, err := rand.Read(guard[:]); err != nil {
		return nil, err
	}

	sealed, err := group.SealApplication(group.SealApplicationInput{
		GroupID:          epoch.Context.GroupID,
		Epoch:            epoch.Number,
		Ratchet:          ratchet,
		SenderData:       messages.SenderData{LeafIndex: myLeaf, Generation: uint32(generation), ReuseGuard: guard},
		SenderDataSecret: epoch.Secrets.SenderDataSecret,
		Plaintext:        frameGroupPayload(plaintext, suite),
		Seal:             aesGCMSealAAD,
	})
	if err != nil {
		return nil, fmt.Errorf("schat: sealing the message: %w", err)
	}

	raw, err := messages.MarshalPrivateMessage(sealed)
	if err != nil {
		return nil, err
	}
	return &GroupSealResult{
		MessageHex:     hex.EncodeToString(raw),
		NextGeneration: generation + 1,
	}, nil
}

// GroupOpen reads a group message.
func GroupOpen(stateJSON, messageHex string) (*GroupOpenResult, error) {
	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return nil, err
	}

	suite := crypto.CipherSuite(GroupCipherSuite)
	raw, err := hex.DecodeString(messageHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the message is not hex: %w", err)
	}
	message, err := messages.ParsePrivateMessage(mlstls.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("schat: the message does not parse: %w", err)
	}

	leaves := uint32((len(epoch.Tree) + 1) / 2)
	secretTree, err := secrettree.New(epoch.Secrets.EncryptionSecret, leaves, suite)
	if err != nil {
		return nil, err
	}

	opened, err := group.OpenApplication(group.OpenApplicationInput{
		Message:          message,
		ExpectedEpoch:    epoch.Number,
		ExpectedGroupID:  epoch.Context.GroupID,
		Tree:             secretTree,
		SenderDataSecret: epoch.Secrets.SenderDataSecret,
		Open:             aesGCMOpenAAD,
	})
	if err != nil {
		return nil, err
	}

	plaintext, err := unframeGroupPayload(opened.Plaintext)
	if err != nil {
		return nil, err
	}

	return &GroupOpenResult{
		PlaintextHex: hex.EncodeToString(plaintext),
		SenderLeaf:   int(opened.SenderData.LeafIndex),
		Generation:   int64(opened.SenderData.Generation),
	}, nil
}

// aesGCMSealAAD and aesGCMOpenAAD are the suite's AEAD WITH associated data.
//
// The GroupInfo is encrypted with no associated data; an application message is encrypted with
// the group id, the epoch, the content type and the authenticated data bound into it. They are
// separate functions rather than one with an optional argument because passing the wrong one is
// not a compile error anywhere else: a message sealed without its AAD still opens for its
// author, and for nobody who checks what they were told to check.
func aesGCMSealAAD(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nil
}

func aesGCMOpenAAD(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, associatedData)
}
