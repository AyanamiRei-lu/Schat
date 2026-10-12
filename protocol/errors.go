package protocol

import "errors"

// Sentinel errors returned by SCS-1.
//
// Callers MUST treat every one of these as a hard failure. SCS-1 is fail-closed
// by design (SCHAT.md section 2, principle 7): on any error the operation is
// abandoned, no plaintext is released, and no "retry with weaker parameters"
// path exists.
var (
	// ErrNotImplemented marks API surface that is specified but not yet built.
	// It is returned only by the step-1 stubs and must disappear as the roadmap
	// progresses (SCHAT.md section 13.2).
	ErrNotImplemented = errors.New("scs1: not implemented yet")

	// ErrShortBuffer means an input was smaller than the format requires.
	ErrShortBuffer = errors.New("scs1: buffer too short")

	// ErrBadPadding means unpadding failed a structural check.
	ErrBadPadding = errors.New("scs1: invalid padding")

	// ErrUnknownProfile means an AEAD profile byte is not recognised.
	ErrUnknownProfile = errors.New("scs1: unknown aead profile")

	// ErrAuthentication means an AEAD tag did not verify. The ciphertext was
	// tampered with, the key was wrong, or the associated data did not match.
	ErrAuthentication = errors.New("scs1: authentication failed")

	// ErrUnknownVersion means a frame carried an unsupported WireVersion.
	ErrUnknownVersion = errors.New("scs1: unsupported protocol version")

	// ErrReplay means a message counter was already seen in this session.
	ErrReplay = errors.New("scs1: replayed message")

	// ErrTooManySkipped means a peer claimed a counter gap larger than the
	// bounded skipped-key cache allows. Rejecting instead of caching prevents a
	// forged counter from exhausting memory (SCHAT.md section 4.5).
	ErrTooManySkipped = errors.New("scs1: too many skipped messages")

	// ErrBadKeySize means a key was not the length its algorithm requires.
	ErrBadKeySize = errors.New("scs1: invalid key size")

	// ErrUntrustedIdentity means a peer's identity key changed without an
	// explicit user re-verification.
	ErrUntrustedIdentity = errors.New("scs1: untrusted identity key")
)
