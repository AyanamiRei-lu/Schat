// Package crypto implements the MLS cipher suite and the labelled cryptographic
// operations built on top of it.
//
// # What this layer is for
//
// Every byte of MLS that is not a length prefix is produced by one of the functions here,
// and each of them prefixes its input with a label. The labels are the whole point: they
// make it impossible to take a signature produced for one purpose and present it as a
// signature for another, and they make it impossible to derive the same key twice for two
// different uses.
//
// Three details in this file are easy to get subtly wrong, and all three were confirmed
// against the specification text rather than from memory (RFC 9420 sections 5.1.2, 5.1.3
// and 5.2):
//
//   - SignWithLabel signs a two-field struct (label, content), NOT the concatenation of
//     the label and the content. The length prefixes matter.
//
//   - EncryptWithLabel puts the context into HPKE's `info`, and passes an EMPTY
//     associated-data argument. A reader who assumes "context means AAD" produces
//     ciphertexts that can never be decrypted by anyone else.
//
//   - RefHash does NOT add the "MLS 1.0 " prefix: its callers pass a label that already
//     includes it ("MLS 1.0 KeyPackage Reference"). SignWithLabel and EncryptWithLabel DO
//     add it. Treating the three alike breaks the references that KeyPackages and
//     Proposals are addressed by.
//
// # Verification
//
// The official vectors include a "crypto basics" file that gives the expected output of
// each function here, byte for byte. The test in this package runs against it when it is
// present; see tools/fetch-mls-vectors.ps1 and vectors_test.go for why it is not vendored.
package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// labelPrefix is prepended to every label used in a signature or an HPKE encryption
// context. It is not prepended by RefHash; see the package comment.
const labelPrefix = "MLS 1.0 "

// CipherSuite identifies an MLS cipher suite.
type CipherSuite uint16

const (
	// X25519AES128GCM is MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001).
	//
	// It is not the suite SCHAT groups use, but it must be implemented anyway: the bulk of
	// the official test vectors are generated for it, and byte-exact verification is the
	// acceptance criterion for this whole step.
	X25519AES128GCM CipherSuite = 0x0001

	// X25519ChaCha20Poly1305 is
	// MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 (0x0003).
	//
	// This is the suite SCHAT groups use. Every primitive in it is already used by the
	// SCS-1 pairwise layer, so the project keeps one identity key, one AEAD implementation
	// and one set of constant-time and zeroisation helpers.
	X25519ChaCha20Poly1305 CipherSuite = 0x0003
)

// ErrUnsupportedSuite means the cipher suite is not implemented.
var ErrUnsupportedSuite = errors.New("mls/crypto: unsupported cipher suite")

// Algorithm sizes and identifiers for a suite.
//
// The values are the ones RFC 9420 section 17.1 registers, and the HPKE identifiers are
// the ones RFC 9180 registers; they are spelled out rather than derived so that a mistake
// shows up as a failing vector rather than as a plausible wrong answer.
type suiteParams struct {
	name string

	// aeadKeySize and aeadNonceSize are the AEAD key and nonce lengths.
	aeadKeySize   int
	aeadNonceSize int

	// hashSize is KDF.Nh: the output length of the suite's hash.
	hashSize int
}

// Params returns the sizes for a suite.
func (c CipherSuite) Params() (suiteParams, error) {
	switch c {
	case X25519AES128GCM:
		return suiteParams{
			name:          "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
			aeadKeySize:   16,
			aeadNonceSize: 12,
			hashSize:      32,
		}, nil
	case X25519ChaCha20Poly1305:
		return suiteParams{
			name:          "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
			aeadKeySize:   32,
			aeadNonceSize: 12,
			hashSize:      32,
		}, nil
	default:
		return suiteParams{}, fmt.Errorf("%w: %#04x", ErrUnsupportedSuite, uint16(c))
	}
}

// HashSize is KDF.Nh for this suite.
func (c CipherSuite) HashSize() int {
	params, err := c.Params()
	if err != nil {
		return 0
	}
	return params.hashSize
}

// AEADKeySize is AEAD.Nk for this suite.
func (c CipherSuite) AEADKeySize() int {
	params, err := c.Params()
	if err != nil {
		return 0
	}
	return params.aeadKeySize
}

// AEADNonceSize is AEAD.Nn for this suite.
func (c CipherSuite) AEADNonceSize() int {
	params, err := c.Params()
	if err != nil {
		return 0
	}
	return params.aeadNonceSize
}

// newHash returns a fresh hash for this suite. SHA-256 in both suites.
func (c CipherSuite) newHash() hash.Hash { return sha256.New() }

// Hash hashes data with the suite's hash function.
func (c CipherSuite) Hash(data []byte) []byte {
	h := c.newHash()
	h.Write(data)
	return h.Sum(nil)
}

// hpkeKDF and hpkeAEAD return the HPKE components for this suite.
func (c CipherSuite) hpkeKDF() (hpke.KDF, error) {
	switch c {
	case X25519AES128GCM, X25519ChaCha20Poly1305:
		return hpke.HKDFSHA256(), nil
	default:
		return nil, fmt.Errorf("%w: %#04x", ErrUnsupportedSuite, uint16(c))
	}
}

func (c CipherSuite) hpkeAEAD() (hpke.AEAD, error) {
	switch c {
	case X25519AES128GCM:
		return hpke.AES128GCM(), nil
	case X25519ChaCha20Poly1305:
		return hpke.ChaCha20Poly1305(), nil
	default:
		return nil, fmt.Errorf("%w: %#04x", ErrUnsupportedSuite, uint16(c))
	}
}

// hpkeKEM returns the KEM for this suite: DHKEM(X25519, HKDF-SHA256).
func (c CipherSuite) hpkeKEM() (hpke.KEM, error) {
	switch c {
	case X25519AES128GCM, X25519ChaCha20Poly1305:
		return hpke.DHKEM(ecdh.X25519()), nil
	default:
		return nil, fmt.Errorf("%w: %#04x", ErrUnsupportedSuite, uint16(c))
	}
}

// ----------------------------------------------------------------------
// Labelled KDF operations

// ExpandWithLabel is RFC 9420 section 8's ExpandWithLabel.
//
//	ExpandWithLabel(Secret, Label, Context, Length):
//	  KDFLabel = struct {
//	      uint16 length;
//	      opaque label<V>;      // "MLS 1.0 " + Label
//	      opaque context<V>;
//	  }
//	  return KDF.Expand(Secret, KDFLabel, Length)
//
// The context is a vector, so its length is part of what is hashed. Two calls that differ
// only in the length of their context therefore produce different output even if the bytes
// concatentate to the same string — which is the property that makes the label scheme
// worth having.
func ExpandWithLabel(secret []byte, label string, context []byte, length int, suite CipherSuite) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("mls/crypto: negative output length %d", length)
	}
	if _, err := suite.Params(); err != nil {
		return nil, err
	}

	kdfLabel := mlstls.NewWriter(2 + 1 + len(labelPrefix) + len(label) + 1 + len(context))
	if length > 0xFFFF {
		return nil, fmt.Errorf("mls/crypto: output length %d does not fit in uint16", length)
	}
	kdfLabel.Uint16(uint16(length))
	kdfLabel.Opaque([]byte(labelPrefix + label))
	kdfLabel.Opaque(context)
	if err := kdfLabel.Err(); err != nil {
		return nil, err
	}

	return hkdfExpand(secret, kdfLabel.Bytes(), length, suite)
}

// DeriveSecret is RFC 9420 section 8's DeriveSecret:
//
//	DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", KDF.Nh)
//
// The empty context is not a detail that can be varied: it is what makes DeriveSecret a
// fixed function of the label, and every secret in the key schedule is derived this way.
func DeriveSecret(secret []byte, label string, suite CipherSuite) ([]byte, error) {
	params, err := suite.Params()
	if err != nil {
		return nil, err
	}
	return ExpandWithLabel(secret, label, nil, params.hashSize, suite)
}

// DeriveTreeSecret is RFC 9420 section 9's DeriveTreeSecret, used by the secret tree's
// per-sender ratchets:
//
//	DeriveTreeSecret(Secret, Label, Generation, Length) =
//	    ExpandWithLabel(Secret, Label, Generation, Length)
//
// The generation is the context, encoded as a four-byte big-endian integer. Because it is
// a context and not part of the label, a receiver that has fallen behind can jump straight
// to any generation without deriving the ones in between, and cannot silently derive a key
// for the wrong generation.
func DeriveTreeSecret(secret []byte, label string, generation uint32, length int, suite CipherSuite) ([]byte, error) {
	var context [4]byte
	binary.BigEndian.PutUint32(context[:], generation)
	return ExpandWithLabel(secret, label, context[:], length, suite)
}

// RefHash is RFC 9420 section 5.2's RefHash, which addresses KeyPackages and Proposals:
//
//	RefHash(label, value) = Hash(RefHashInput)
//	RefHashInput = struct { opaque label<V>; opaque value<V>; }
//
// The label is used as given, WITH the "MLS 1.0 " prefix already included by the caller,
// unlike SignWithLabel and EncryptWithLabel. Getting that wrong yields a reference that is
// consistent with itself and matches nothing else.
func RefHash(label string, value []byte, suite CipherSuite) ([]byte, error) {
	if _, err := suite.Params(); err != nil {
		return nil, err
	}

	input := mlstls.NewWriter(1 + len(label) + 1 + len(value))
	input.Opaque([]byte(label))
	input.Opaque(value)
	if err := input.Err(); err != nil {
		return nil, err
	}
	return suite.Hash(input.Bytes()), nil
}

// ----------------------------------------------------------------------
// Labelled signature and HPKE operations

// signContent encodes the structure a labelled signature covers.
func signContent(label string, content []byte) ([]byte, error) {
	w := mlstls.NewWriter(1 + len(labelPrefix) + len(label) + 1 + len(content))
	w.Opaque([]byte(labelPrefix + label))
	w.Opaque(content)
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// SignWithLabel is RFC 9420 section 5.1.2's SignWithLabel.
//
//	SignContent = struct { opaque label<V>; opaque content<V>; }
//	label = "MLS 1.0 " + Label
//
// privateKey is either the 32-byte Ed25519 seed or the 64-byte expanded form. The seed is
// what the official vectors carry (their format document says EdDSA private keys are in
// their "native byte string representation"), and accepting both avoids a caller having to
// know which one it holds.
func SignWithLabel(privateKey []byte, label string, content []byte) ([]byte, error) {
	key, err := ed25519PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	toSign, err := signContent(label, content)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, toSign), nil
}

// ed25519PrivateKey normalises the two accepted private key encodings.
//
// Passing a 32-byte seed straight to ed25519.Sign panics, which is how the vectors found
// this: a panic inside a signature routine is a bug in the caller's expectations, not
// something to recover from, so the length is checked here where it can be reported.
func ed25519PrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf(
			"mls/crypto: Ed25519 private key is %d bytes, want %d (seed) or %d (expanded)",
			len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// VerifyWithLabel checks a signature produced by SignWithLabel.
func VerifyWithLabel(publicKey []byte, label string, content, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("mls/crypto: Ed25519 public key is %d bytes, want %d",
			len(publicKey), ed25519.PublicKeySize)
	}
	toVerify, err := signContent(label, content)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), toVerify, signature) {
		return errors.New("mls/crypto: signature verification failed")
	}
	return nil
}

// encryptContext encodes the structure HPKE authenticates in a labelled encryption.
func encryptContext(label string, context []byte) ([]byte, error) {
	w := mlstls.NewWriter(1 + len(labelPrefix) + len(label) + 1 + len(context))
	w.Opaque([]byte(labelPrefix + label))
	w.Opaque(context)
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// EncryptWithLabel is RFC 9420 section 5.1.3's EncryptWithLabel.
//
//	EncryptContext = struct { opaque label<V>; opaque context<V>; }
//	EncryptWithLabel(pk, Label, Context, Plaintext) =
//	    SealBase(pk, EncryptContext, "", Plaintext)
//
// The empty string is HPKE's `aad` argument, and the EncryptContext is HPKE's `info`. The
// two are not interchangeable: the info is bound into the key schedule, the aad only into
// the AEAD tag. Swapping them produces ciphertexts that no correct implementation can
// decrypt, while still being internally consistent.
func EncryptWithLabel(publicKey []byte, label string, context, plaintext []byte, suite CipherSuite) (kemOutput, ciphertext []byte, err error) {
	kem, err := suite.hpkeKEM()
	if err != nil {
		return nil, nil, err
	}
	kdf, err := suite.hpkeKDF()
	if err != nil {
		return nil, nil, err
	}
	aead, err := suite.hpkeAEAD()
	if err != nil {
		return nil, nil, err
	}

	pk, err := kem.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mls/crypto: public key: %w", err)
	}

	info, err := encryptContext(label, context)
	if err != nil {
		return nil, nil, err
	}

	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, nil, fmt.Errorf("mls/crypto: hpke setup: %w", err)
	}

	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("mls/crypto: hpke seal: %w", err)
	}
	return enc, ct, nil
}

// DecryptWithLabel is the inverse of EncryptWithLabel.
func DecryptWithLabel(privateKey []byte, label string, context, kemOutput, ciphertext []byte, suite CipherSuite) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("mls/crypto: empty private key")
	}

	kem, err := suite.hpkeKEM()
	if err != nil {
		return nil, err
	}
	kdf, err := suite.hpkeKDF()
	if err != nil {
		return nil, err
	}
	aead, err := suite.hpkeAEAD()
	if err != nil {
		return nil, err
	}

	sk, err := kem.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("mls/crypto: private key: %w", err)
	}

	info, err := encryptContext(label, context)
	if err != nil {
		return nil, err
	}

	recipient, err := hpke.NewRecipient(kemOutput, sk, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("mls/crypto: hpke setup: %w", err)
	}

	pt, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("mls/crypto: hpke open: %w", err)
	}
	return pt, nil
}

// DeriveKeyPair derives an HPKE key pair from input keying material.
//
// This is the function the whole of TreeKEM depends on: a node's key pair is not random,
// it is derived from that node's path secret, which is why every member of a subgroup can
// compute the same public keys. Returning the serialised public key as well as the private
// one saves every caller from re-deriving it.
func DeriveKeyPair(ikm []byte, suite CipherSuite) (privateKey []byte, publicKey []byte, err error) {
	kem, err := suite.hpkeKEM()
	if err != nil {
		return nil, nil, err
	}

	// hpke's KEM interface does not expose the private bytes, so the pair is derived
	// through the standard library's own X25519 and re-wrapped. DeriveKeyPair for
	// DHKEM(X25519) is defined in RFC 9180 section 7.1.2 and is implemented by the
	// standard library; calling it rather than reimplementing it is the point.
	priv, err := kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, fmt.Errorf("mls/crypto: derive key pair: %w", err)
	}

	// PrivateKey.Bytes reports an error as well as the bytes (a key from a different KEM
	// must not be silently returned as an empty slice); PublicKey.Bytes does not.
	privBytes, err := priv.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("mls/crypto: serialising the derived private key: %w", err)
	}
	pubBytes := priv.PublicKey().Bytes()

	return privBytes, pubBytes, nil
}

// hkdfExpand runs HKDF-Expand (RFC 5869 section 2.3) with the suite's hash.
//
// The earlier version of this function wrote `block || info || counter` straight into a
// plain hash. That is not HKDF-Expand: the PRK is the HMAC KEY, not more input. The mistake
// is invisible from the inside — every value it produced was deterministic, plausible and
// self-consistent — and it was caught only by the official vectors. That is the whole
// argument for verifying against data this project did not generate.
func hkdfExpand(secret, info []byte, length int, suite CipherSuite) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("mls/crypto: negative HKDF length %d", length)
	}
	// RFC 5869 caps HKDF-Expand at 255 * HashLen, and every MLS derivation is far below
	// that, so a request above the cap is a caller bug rather than a legitimate value.
	if length > 255*suite.HashSize() {
		return nil, fmt.Errorf("mls/crypto: output length %d exceeds the HKDF limit", length)
	}
	if length == 0 {
		return []byte{}, nil
	}

	mac := hmac.New(suite.newHash, secret)
	out := make([]byte, 0, length)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac.Reset()
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length], nil
}

// Extract is HKDF-Extract (RFC 5869 section 2.2): HMAC(salt, ikm).
//
// It is exported because the key schedule builds on it, and because the order of its two
// arguments is exactly the kind of detail that cannot be settled by reading: both orders
// produce plausible, deterministic, self-consistent secrets, and only the official
// key-schedule vectors can say which one the protocol means. The test in the schedule
// package tries both and reports which reproduces the published bytes.
func Extract(salt, ikm []byte, suite CipherSuite) ([]byte, error) {
	if _, err := suite.Params(); err != nil {
		return nil, err
	}
	mac := hmac.New(suite.newHash, salt)
	mac.Write(ikm)
	return mac.Sum(nil), nil
}
