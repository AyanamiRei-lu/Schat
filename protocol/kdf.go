package protocol

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// SCS-1 key derivation (SCHAT.md sections 4.3 to 4.5).
//
// Everything here is a thin, auditable wrapper over RFC 5869 HKDF-SHA256. The
// wrapper exists so that three invariants can be enforced in one place rather
// than trusted to every call site:
//
//  1. A label is always present, so two features can never derive the same key
//     from the same input keying material.
//  2. Lengths are explicit, so no derivation can silently truncate.
//  3. Secret intermediates are zeroed rather than left for the garbage
//     collector.
const (
	// KeySize is the symmetric key length used by every SCS-1 AEAD profile.
	KeySize = 32

	// NonceSize is the standard AEAD nonce length.
	NonceSize = 12

	// XNonceSize is the extended AEAD nonce length used by ProfileFile.
	XNonceSize = 24

	// TagSize is the AEAD authentication tag length.
	TagSize = 16

	// MsgKeySize is the fixed number of bytes derived per message: a 32-byte key
	// followed by a 24-byte nonce buffer.
	//
	// The output length is FIXED at the extended nonce size rather than tailored
	// per profile, and the nonce is truncated to the profile's requirement at use
	// time (see MessageKey.NonceFor). Two reasons:
	//
	//   - Out-of-order delivery forces the receiver to derive the keys for
	//     skipped messages before it knows what those messages contain. A
	//     profile-dependent output length would make that impossible.
	//   - A single fixed width removes a whole class of length-confusion bugs
	//     from the hot path.
	//
	// Truncating a 24-byte derivation to 12 bytes is safe because the ChaCha20
	// and XChaCha20 nonce spaces are different constructions: XChaCha20 derives a
	// subkey from the full 192-bit nonce via HChaCha20, so equal 12-byte prefixes
	// under different profiles do not imply equal keystreams. In any case a given
	// (chain, direction, counter) triple is encrypted exactly once.
	MsgKeySize = KeySize + XNonceSize

	// ChainKeySize is the symmetric ratchet chain key length.
	ChainKeySize = 32

	// RootKeySize is the session root key length.
	RootKeySize = 32

	// SafetyNumberSize is the length of the identity verification digest.
	SafetyNumberSize = 32
)

// HKDF derives length bytes from input keying material using HKDF-SHA256.
//
// salt may be nil, info is the domain separation context. This is the single
// choke point for key derivation in SCS-1.
func HKDF(ikm, salt []byte, info string, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("scs1: hkdf: invalid length %d", length)
	}
	out, err := hkdf.Key(sha256.New, ikm, salt, info, length)
	if err != nil {
		return nil, fmt.Errorf("scs1: hkdf: %w", err)
	}
	return out, nil
}

// DeriveLabeled implements the SCS-1 derivation idiom used throughout the
// specification:
//
//	out = HKDF-SHA256(ikm, salt = label, info = label || 0x00 || context, len)
//
// The label appears twice — as salt and as the leading context — so that both the
// extract and expand stages are domain separated.
func DeriveLabeled(ikm []byte, label string, context []byte, length int) ([]byte, error) {
	info := make([]byte, 0, len(label)+1+len(context))
	info = append(info, label...)
	info = append(info, 0x00)
	info = append(info, context...)
	return HKDF(ikm, []byte(label), string(info), length)
}

// MessageKey is the key and nonce derived for exactly one message.
//
// It is used once and then zeroed. Reusing a MessageKey would reuse an AEAD
// nonce, which is catastrophic for ChaCha20-Poly1305 and AES-GCM alike.
type MessageKey struct {
	// Key is the 256-bit AEAD key.
	Key [KeySize]byte

	// Nonce holds 24 derived bytes; only the first NonceFor(profile) are used.
	Nonce [XNonceSize]byte
}

// NonceFor returns the nonce slice the given profile requires.
func (m *MessageKey) NonceFor(profile AEADProfile) []byte {
	n := profile.NonceSize()
	if n > XNonceSize {
		n = XNonceSize
	}
	return m.Nonce[:n]
}

// Zero scrubs the key and nonce.
func (m *MessageKey) Zero() {
	if m == nil {
		return
	}
	Zero(m.Key[:])
	Zero(m.Nonce[:])
}

// AdvanceChain performs one step of the symmetric ratchet:
//
//	CK_{n+1} = HMAC-SHA256(CK_n, 0x02)
//
// HMAC is used rather than a bare hash so that knowledge of CK_{n+1} does not
// reveal CK_n and so that the chain cannot be run backwards.
func AdvanceChain(chainKey []byte) ([]byte, error) {
	if len(chainKey) == 0 {
		return nil, fmt.Errorf("%w: empty chain key", ErrBadKeySize)
	}
	mac := hmac.New(sha256.New, chainKey)
	mac.Write([]byte{chainAdvanceTag})
	return mac.Sum(nil), nil
}

// DeriveMessageKey derives the message key for counter n in a chain:
//
//	info = dir || LE64(n)
//	MK   = HKDF-SHA256(CK_n, salt = LabelMsg, info, len = 56)
//
// Folding dir into the derivation means the same counter yields different keys in
// each direction, which is what stops a reflection attack from bouncing a
// victim's own ciphertext back at them as if it were a valid inbound message.
//
// The content profile is deliberately NOT part of this derivation; it travels in
// the authenticated frame header instead. See the comment on MsgKeySize.
func DeriveMessageKey(chainKey []byte, dir byte, n uint64) (*MessageKey, error) {
	if len(chainKey) == 0 {
		return nil, fmt.Errorf("%w: empty chain key", ErrBadKeySize)
	}
	ctx := make([]byte, 0, 9)
	ctx = append(ctx, dir)
	ctx = binary.LittleEndian.AppendUint64(ctx, n)

	raw, err := DeriveLabeled(chainKey, LabelMsg, ctx, MsgKeySize)
	if err != nil {
		return nil, err
	}
	defer Zero(raw)

	mk := &MessageKey{}
	copy(mk.Key[:], raw[:KeySize])
	copy(mk.Nonce[:], raw[KeySize:MsgKeySize])
	return mk, nil
}

// LexSort returns its inputs sorted lexicographically, with the originals left
// untouched.
//
// This is the LEXSORT step from SCS-HSK (SCHAT.md section 4.4). Textbook
// Diffie-Hellman handshakes concatenate shared secrets in role order, so an
// implementation that swaps initiator and responder derives a different root key
// and the two sides silently fail to talk. Sorting by byte value makes the
// derivation role-independent: both sides compute the same input no matter which
// one they think they are.
func LexSort(inputs ...[]byte) [][]byte {
	out := make([][]byte, len(inputs))
	copy(out, inputs)
	// Insertion sort: the slice is a handful of elements, and this avoids any
	// dependency on the ordering stability of a generic sort.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(out[j-1], out[j]) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// writeLengthPrefixed writes a length-prefixed field into a transcript hash.
//
// Length prefixing is not cosmetic. Without it, ("ab", "c") and ("a", "bc") hash
// identically, which lets an attacker move bytes between adjacent fields of the
// handshake transcript while keeping the derived root key unchanged.
func writeLengthPrefixed(h interface{ Write([]byte) (int, error) }, field []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(field)
}

// HandshakeTranscript computes the digest that binds a handshake to the exact
// values that produced it (SCHAT.md section 4.4).
//
// It covers the protocol version, both identity keys, the signed prekey and the
// one-time prekey actually consumed. Folding this into the root key salt means
// substituting any of those values changes the derived key, so a man-in-the-middle
// cannot complete a handshake that both peers will accept.
func HandshakeTranscript(version byte, identityA, identityB, signedPreKey, oneTimePreKey []byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("scs1: blake2b.New256(nil) failed: " + err.Error())
	}

	_, _ = h.Write([]byte(LabelTranscript))
	_, _ = h.Write([]byte{version})

	for _, id := range LexSort(identityA, identityB) {
		writeLengthPrefixed(h, id)
	}
	writeLengthPrefixed(h, signedPreKey)
	writeLengthPrefixed(h, oneTimePreKey)

	return h.Sum(nil)
}

// IdentityDigest derives a compact digest over a pair of identity keys.
//
// Both keys are fixed-length, so no length prefixing is needed here.
func IdentityDigest(version byte, identityA, identityB []byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("scs1: blake2b.New256(nil) failed: " + err.Error())
	}
	_, _ = h.Write([]byte(LabelTranscript))
	_, _ = h.Write([]byte{version})
	for _, id := range LexSort(identityA, identityB) {
		_, _ = h.Write(id)
	}
	return h.Sum(nil)
}

// SafetyNumber derives the identity verification digest displayed to users
// (SCHAT.md section 4.4).
//
// Users compare the rendered digits out of band, or scan the QR form. Until they
// do, the peer's identity is unverified and the UI says so.
func SafetyNumber(identityA, identityB []byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("scs1: blake2b.New256(nil) failed: " + err.Error())
	}
	for _, id := range LexSort(identityA, identityB) {
		_, _ = h.Write(id)
	}
	_, _ = h.Write([]byte(LabelSafety))
	return h.Sum(nil)
}

// SafetyDigits renders a safety number as 60 decimal digits in twelve groups of
// five, which is the form users compare aloud or read off each other's screens.
//
// The 32-byte digest cannot simply be sliced into twelve 8-byte chunks — there are
// only four of those, and a naive implementation emits "00000" for the remaining
// eight groups, quietly reducing a 60-digit code to a 20-digit one. Each group is
// therefore drawn from its own keyed expansion of the digest, so every group depends
// on the whole digest and all twelve carry real entropy.
//
// Both peers must compute identical digits or verification is impossible, which is
// why this lives in the protocol rather than in each client.
func SafetyDigits(identityA, identityB []byte) string {
	digest := SafetyNumber(identityA, identityB)

	groups := make([]string, 12)
	for i := range groups {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic("scs1: blake2b.New256(nil) failed: " + err.Error())
		}
		_, _ = h.Write([]byte(LabelSafety))
		_, _ = h.Write([]byte("digits"))
		_, _ = h.Write(digest)
		_, _ = h.Write([]byte{byte(i)})
		sum := h.Sum(nil)

		value := binary.BigEndian.Uint64(sum[:8]) % 100000
		groups[i] = fmt.Sprintf("%05d", value)
	}

	return fmt.Sprintf("%s %s %s %s  %s %s %s %s  %s %s %s %s",
		groups[0], groups[1], groups[2], groups[3],
		groups[4], groups[5], groups[6], groups[7],
		groups[8], groups[9], groups[10], groups[11])
}
