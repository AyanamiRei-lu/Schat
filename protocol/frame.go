package protocol

import (
	"encoding/binary"
	"fmt"
)

// Frame header (SCHAT.md section 4.5).
//
//	hdr = ver(1) || flags(1) || profile(1) || DH_pub(32) || pn(4) || n(4)
//	AD  = AD0 || hdr
//
// The header is fed to the AEAD as associated data: authenticated, not
// encrypted. That is deliberate. The relay server must be able to read
// routing-relevant structure without being able to read content, and any
// tampering with any header byte makes decryption fail.
//
// # Why the content profile lives in the header
//
// An earlier revision folded the content profile into the message key derivation
// (MK = HKDF(CK, dir || n || type)). That is unimplementable alongside
// out-of-order delivery: when a receiver caches the keys for several skipped
// messages it does not yet know what content type each skipped message carries,
// so it cannot derive them. The profile therefore moved into the header, where
// (a) it is authenticated through the AEAD associated data, and (b) it is known
// before any key is derived. An attacker who rewrites it breaks the tag.
const (
	// HeaderSize is the fixed wire size of a frame header.
	HeaderSize = 43

	// RatchetPubSize is the length of an X25519 ratchet public key.
	RatchetPubSize = 32
)

// Header flag bits.
const (
	// FlagHasOneTimePreKey is set when the sender consumed a one-time prekey,
	// which upgrades the session to full forward secrecy for its first message.
	FlagHasOneTimePreKey byte = 1 << 0

	// FlagUnverifiedIdentity is set when the sender's identity key has not been
	// verified out of band. Receivers surface this prominently in the UI.
	FlagUnverifiedIdentity byte = 1 << 1

	// FlagGroupMessage marks a frame whose content key came from the MLS
	// exporter rather than a pairwise ratchet (SCHAT.md section 4.6.2).
	FlagGroupMessage byte = 1 << 2

	// FlagPaddingExtended is reserved for future variable-length padding
	// schemes. It is defined now so the bit is never reused for something else.
	FlagPaddingExtended byte = 1 << 3
)

// Header is the decoded form of an SCS-1 frame header.
type Header struct {
	// Version is the wire protocol revision; must equal WireVersion.
	Version byte

	// Flags carries the flag bits above.
	Flags byte

	// Profile selects the AEAD and chunking used for the payload.
	Profile AEADProfile

	// RatchetPub is the sender's current X25519 ratchet public key.
	RatchetPub [RatchetPubSize]byte

	// PrevChainLen is the number of messages in the sender's previous sending
	// chain, used to derive skipped keys across a DH ratchet step.
	PrevChainLen uint32

	// Counter is the message number within the current sending chain.
	Counter uint32
}

// Marshal encodes the header to its wire form.
func (h Header) Marshal() []byte {
	out := make([]byte, HeaderSize)
	out[0] = h.Version
	out[1] = h.Flags
	out[2] = byte(h.Profile)
	copy(out[3:3+RatchetPubSize], h.RatchetPub[:])
	binary.BigEndian.PutUint32(out[35:39], h.PrevChainLen)
	binary.BigEndian.PutUint32(out[39:43], h.Counter)
	return out
}

// UnmarshalHeader decodes a wire header.
//
// A version mismatch or an unknown content profile is rejected outright. SCS-1
// never negotiates down and never guesses (SCHAT.md section 2, principle 7).
func UnmarshalHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: header needs %d bytes, got %d",
			ErrShortBuffer, HeaderSize, len(b))
	}

	var h Header
	h.Version = b[0]
	if h.Version != WireVersion {
		return Header{}, fmt.Errorf("%w: got %d, want %d",
			ErrUnknownVersion, h.Version, WireVersion)
	}

	h.Flags = b[1]
	h.Profile = AEADProfile(b[2])
	if !h.Profile.Valid() {
		return Header{}, fmt.Errorf("%w: header profile %d", ErrUnknownProfile, b[2])
	}

	copy(h.RatchetPub[:], b[3:3+RatchetPubSize])
	h.PrevChainLen = binary.BigEndian.Uint32(b[35:39])
	h.Counter = binary.BigEndian.Uint32(b[39:43])
	return h, nil
}

// Has reports whether a flag bit is set.
func (h Header) Has(flag byte) bool { return h.Flags&flag != 0 }

// SetFlag sets or clears a flag bit.
func (h *Header) SetFlag(flag byte, on bool) {
	if on {
		h.Flags |= flag
		return
	}
	h.Flags &^= flag
}

// AssociatedData builds the AEAD associated-data value for a frame.
//
// The session's own AD (derived from the handshake transcript) is prepended, so a
// ciphertext cannot be replayed from one session into another even if the two
// sessions somehow shared a chain key.
func AssociatedData(sessionAD []byte, h Header) []byte {
	hdr := h.Marshal()
	out := make([]byte, 0, len(sessionAD)+len(hdr))
	out = append(out, sessionAD...)
	out = append(out, hdr...)
	return out
}

// Envelope is the unit the relay server sees.
//
// The server parses Token to decide where to forward, and treats Header and
// Ciphertext as opaque bytes. It never holds a key that could open them, which is
// what makes the zero-retention guarantee architectural rather than a policy
// promise (SCHAT.md section 7.2).
type Envelope struct {
	// Token is the rotating delivery token identifying the recipient's mailbox.
	// It is unrelated to the recipient's identity (SCHAT.md section 4.7).
	Token [16]byte

	// Header is the authenticated frame header.
	Header Header

	// Ciphertext is the AEAD output, tag included.
	Ciphertext []byte
}
