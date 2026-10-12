package protocol

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

// Public-key primitives (SCHAT.md sections 4.2 and 4.4).
//
// Everything here is a thin wrapper over the standard library. The wrappers exist
// so that the two invariants SCS-1 cares about are enforced in one place:
//
//  1. Randomness comes from crypto/rand and nowhere else. math/rand is banned
//     project-wide; a predictable identity key is a total compromise.
//  2. Public keys are validated before use. crypto/ecdh rejects a low-order or
//     wrongly-sized X25519 point, which is what stops small-subgroup and
//     all-zero-shared-secret attacks.
const (
	// X25519KeySize is the length of an X25519 key or public value.
	X25519KeySize = 32

	// Ed25519PublicKeySize is the length of an Ed25519 public key.
	Ed25519PublicKeySize = ed25519.PublicKeySize

	// Ed25519PrivateKeySize is the length of a Go Ed25519 private key, which is
	// the 32-byte seed followed by the 32-byte public key.
	Ed25519PrivateKeySize = ed25519.PrivateKeySize

	// Ed25519SeedSize is the length of the Ed25519 seed alone.
	Ed25519SeedSize = ed25519.SeedSize

	// Ed25519SignatureSize is the length of an Ed25519 signature.
	Ed25519SignatureSize = ed25519.SignatureSize
)

// GenerateX25519Key creates a fresh X25519 key pair.
func GenerateX25519Key() (*ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("scs1: generating x25519 key: %w", err)
	}
	return priv, nil
}

// X25519PublicBytes returns the raw 32-byte public value of a private key.
func X25519PublicBytes(priv *ecdh.PrivateKey) []byte {
	return priv.PublicKey().Bytes()
}

// X25519 performs a Diffie-Hellman operation.
//
// The peer's public value is validated by crypto/ecdh, which rejects points of
// small order. That check matters: a peer that supplies a low-order point would
// otherwise force a shared secret the attacker already knows.
func X25519(priv *ecdh.PrivateKey, peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != X25519KeySize {
		return nil, fmt.Errorf("%w: x25519 public value must be %d bytes, got %d",
			ErrBadKeySize, X25519KeySize, len(peerPublic))
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("scs1: invalid x25519 public value: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("scs1: x25519 agreement failed: %w", err)
	}
	return shared, nil
}

// X25519FromBytes reconstructs a private key from its 32-byte scalar.
func X25519FromBytes(scalar []byte) (*ecdh.PrivateKey, error) {
	if len(scalar) != X25519KeySize {
		return nil, fmt.Errorf("%w: x25519 scalar must be %d bytes, got %d",
			ErrBadKeySize, X25519KeySize, len(scalar))
	}
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("scs1: invalid x25519 scalar: %w", err)
	}
	return priv, nil
}

// GenerateIdentity creates a fresh long-term identity.
//
// The signing key (Ed25519) and the agreement key (X25519) are generated
// independently rather than derived from one another. Keeping the roles separate
// means a flaw in one algorithm cannot reach the other, and it avoids the
// well-known pitfalls of reusing an Ed25519 key as an X25519 key.
func GenerateIdentity() (*IdentityKeyPair, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("scs1: generating ed25519 identity: %w", err)
	}

	agreePriv, err := GenerateX25519Key()
	if err != nil {
		return nil, err
	}

	return &IdentityKeyPair{
		SigningPrivate:   []byte(signPriv),
		SigningPublic:    []byte(signPub),
		AgreementPrivate: agreePriv.Bytes(),
		AgreementPublic:  X25519PublicBytes(agreePriv),
	}, nil
}

// Sign produces an Ed25519 signature over msg.
func (k *IdentityKeyPair) Sign(msg []byte) ([]byte, error) {
	if len(k.SigningPrivate) != Ed25519PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key must be %d bytes, got %d",
			ErrBadKeySize, Ed25519PrivateKeySize, len(k.SigningPrivate))
	}
	return ed25519.Sign(ed25519.PrivateKey(k.SigningPrivate), msg), nil
}

// Verify checks an Ed25519 signature against a public key.
//
// It returns ErrAuthentication on any failure so that callers cannot
// accidentally distinguish "bad signature" from "malformed key" and leak
// information through differing error paths.
func Verify(publicKey, msg, signature []byte) error {
	if len(publicKey) != Ed25519PublicKeySize {
		return fmt.Errorf("%w: ed25519 public key must be %d bytes, got %d",
			ErrBadKeySize, Ed25519PublicKeySize, len(publicKey))
	}
	if len(signature) != Ed25519SignatureSize {
		return fmt.Errorf("%w: ed25519 signature must be %d bytes, got %d",
			ErrBadKeySize, Ed25519SignatureSize, len(signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), msg, signature) {
		return fmt.Errorf("%w: ed25519 signature verification failed", ErrAuthentication)
	}
	return nil
}

// AgreementPrivateKey reconstructs the X25519 private key of an identity.
func (k *IdentityKeyPair) AgreementPrivateKey() (*ecdh.PrivateKey, error) {
	return X25519FromBytes(k.AgreementPrivate)
}

// EqualBytes compares two byte slices in constant time.
//
// SCS-1 requires this for every comparison of secret-derived data. A plain
// bytes.Equal returns as soon as it finds a difference, which leaks the position
// of the first mismatching byte through timing — enough to recover a MAC or a
// signature byte by byte.
func EqualBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// concat appends every slice in order into a single new buffer.
//
// Derivation inputs are assembled with this rather than by repeated append so
// that the intent — "hash exactly these byte strings, in this order" — is
// explicit at each call site.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
