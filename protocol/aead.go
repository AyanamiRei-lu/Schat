package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADProfile selects the authenticated encryption algorithm used for a given
// content type.
//
// This is the concrete expression of requirement 7 in the project brief:
// different file formats are encrypted differently. The reason is not
// decoration — the formats genuinely differ in access pattern and threat
// profile (SCHAT.md section 5.2):
//
//   - Text is tiny and latency sensitive, and benefits from an AEAD whose
//     software implementation is constant time by construction.
//   - Images are read progressively, so the header needs its own protection.
//   - Video needs random access and per-chunk keys.
//   - Generic files are read once, sequentially, with random nonces — which is
//     exactly where XChaCha20's 192-bit nonce eliminates the nonce-reuse bug
//     class entirely.
//   - The local database is accessed in tiny random reads, where AES hardware
//     acceleration (ARMv8 Crypto Extensions) is several times faster and
//     cheaper on battery.
type AEADProfile uint8

// The SCS-1 AEAD profile matrix (SCHAT.md section 5.1).
const (
	// ProfileText encrypts chat messages (1:1 and group).
	ProfileText AEADProfile = 0x01

	// ProfileImage encrypts image tile payloads: ChaCha20-Poly1305.
	ProfileImage AEADProfile = 0x02

	// ProfileVideo encrypts video segments: ChaCha20-Poly1305.
	ProfileVideo AEADProfile = 0x03

	// ProfileFile encrypts arbitrary file chunks: XChaCha20-Poly1305 with a
	// 192-bit nonce, so that randomly generated nonces are safe.
	ProfileFile AEADProfile = 0x04

	// ProfileVoice encrypts Opus voice frames: ChaCha20-Poly1305.
	ProfileVoice AEADProfile = 0x05

	// ProfileHeader encrypts media container headers and metadata, where the
	// data is small and AES-GCM's hardware acceleration wins.
	ProfileHeader AEADProfile = 0x06

	// ProfileDatabase encrypts local database pages (SQLCipher-style).
	ProfileDatabase AEADProfile = 0x07
)

// String renders the profile for logs and error messages. It never returns
// secret data.
func (p AEADProfile) String() string {
	switch p {
	case ProfileText:
		return "text/chacha20-poly1305"
	case ProfileImage:
		return "image/chacha20-poly1305"
	case ProfileVideo:
		return "video/chacha20-poly1305"
	case ProfileFile:
		return "file/xchacha20-poly1305"
	case ProfileVoice:
		return "voice/chacha20-poly1305"
	case ProfileHeader:
		return "header/aes-256-gcm"
	case ProfileDatabase:
		return "database/aes-256-gcm"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(p))
	}
}

// Valid reports whether the profile byte is recognised.
func (p AEADProfile) Valid() bool {
	return p >= ProfileText && p <= ProfileDatabase
}

// KeySize returns the key length the profile requires. Every SCS-1 profile uses
// 256-bit keys.
func (p AEADProfile) KeySize() int { return 32 }

// NonceSize returns the nonce length the profile requires. Only ProfileFile
// uses an extended nonce.
func (p AEADProfile) NonceSize() int {
	if p == ProfileFile {
		return chacha20poly1305.NonceSizeX // 24
	}
	return chacha20poly1305.NonceSize // 12
}

// Overhead returns the authentication tag length in bytes.
func (p AEADProfile) Overhead() int {
	if p == ProfileHeader || p == ProfileDatabase {
		return 16 // GCM tag
	}
	return chacha20poly1305.Overhead // 16
}

// NewAEAD constructs the AEAD for this profile from a 256-bit key.
//
// The returned cipher.AEAD operates in place and is safe for concurrent use,
// as required by crypto/cipher. Callers remain responsible for zeroing the key
// once the AEAD is no longer needed.
func (p AEADProfile) NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != p.KeySize() {
		return nil, fmt.Errorf("%w: %s needs %d-byte key, got %d",
			ErrBadKeySize, p, p.KeySize(), len(key))
	}

	switch p {
	case ProfileText, ProfileImage, ProfileVideo, ProfileVoice:
		return chacha20poly1305.New(key)

	case ProfileFile:
		return chacha20poly1305.NewX(key)

	case ProfileHeader, ProfileDatabase:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("scs1: aes: %w", err)
		}
		return cipher.NewGCM(block)

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownProfile, uint8(p))
	}
}

// Seal encrypts plaintext under the profile, returning ciphertext with the
// authentication tag appended.
//
// The nonce must never repeat for a given key. For ProfileFile the nonce is
// 192-bit and may be generated randomly; for every other profile the nonce is
// derived deterministically from the ratchet counter (never random) precisely
// so that reuse cannot happen.
func (p AEADProfile) Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: nonce must be %d bytes for %s",
			ErrBadKeySize, aead.NonceSize(), p)
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts ciphertext under the profile and verifies its tag.
//
// Any failure returns ErrAuthentication (wrapped) and no plaintext. Callers
// must not attempt to salvage partial output.
func (p AEADProfile) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: nonce must be %d bytes for %s",
			ErrBadKeySize, aead.NonceSize(), p)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAuthentication, p)
	}
	return plaintext, nil
}

// AllProfiles returns the complete profile matrix, for tests and for the
// capability advertisement exchanged during session setup.
func AllProfiles() []AEADProfile {
	return []AEADProfile{
		ProfileText,
		ProfileImage,
		ProfileVideo,
		ProfileFile,
		ProfileVoice,
		ProfileHeader,
		ProfileDatabase,
	}
}
