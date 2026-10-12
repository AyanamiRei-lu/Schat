package protocol

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestHKDFRFC5869TestCase1 checks the derivation against the official test
// vector from RFC 5869 Appendix A.1.
//
// This matters more than it looks. A key derivation function that is subtly
// wrong still produces output that looks random and still round-trips inside a
// single implementation, so round-trip tests alone would pass on a broken
// implementation. Only a published vector proves the bytes are right.
func TestHKDFRFC5869TestCase1(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)

	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	if err != nil {
		t.Fatalf("decoding salt: %v", err)
	}

	// RFC 5869 lists this info field as raw bytes f0..f9, which is not valid
	// UTF-8; Go strings hold arbitrary bytes so this round-trips exactly.
	info := string([]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9})

	want, err := hex.DecodeString(
		"3cb25f25faacd57a90434f64d0362f2a" +
			"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
			"34007208d5b887185865")
	if err != nil {
		t.Fatalf("decoding expected OKM: %v", err)
	}

	got, err := HKDF(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("HKDF returned error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 5869 A.1 mismatch\n got: %x\nwant: %x", got, want)
	}
}

// TestHKDFRFC5869TestCase3 covers the zero-length salt and info case, which is
// where implementations that treat nil and empty differently tend to diverge.
func TestHKDFRFC5869TestCase3(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	want, err := hex.DecodeString(
		"8da4e775a563c18f715f802a063c5a31" +
			"b8a11f5c5ee1879ec3454e5f3c738d2d" +
			"9d201395faa4b61a96c8")
	if err != nil {
		t.Fatalf("decoding expected OKM: %v", err)
	}

	got, err := HKDF(ikm, nil, "", 42)
	if err != nil {
		t.Fatalf("HKDF returned error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 5869 A.3 mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestHKDFRejectsBadLength(t *testing.T) {
	if _, err := HKDF([]byte("ikm"), nil, "info", 0); err == nil {
		t.Fatal("expected an error for zero length, got nil")
	}
	if _, err := HKDF([]byte("ikm"), nil, "info", -1); err == nil {
		t.Fatal("expected an error for negative length, got nil")
	}
}

// TestDeriveLabeledSeparatesDomains is the test that protects the whole label
// scheme: identical inputs under different labels must never agree.
func TestDeriveLabeledSeparatesDomains(t *testing.T) {
	ikm := []byte("shared input keying material")
	ctx := []byte("same context")

	seen := make(map[string]string)
	for _, label := range AllLabels() {
		out, err := DeriveLabeled(ikm, label, ctx, KeySize)
		if err != nil {
			t.Fatalf("DeriveLabeled(%q): %v", label, err)
		}
		if len(out) != KeySize {
			t.Fatalf("DeriveLabeled(%q) returned %d bytes, want %d", label, len(out), KeySize)
		}
		key := hex.EncodeToString(out)
		if prev, dup := seen[key]; dup {
			t.Fatalf("labels %q and %q produced identical key material", prev, label)
		}
		seen[key] = label
	}
}

func TestDeriveLabeledIsDeterministic(t *testing.T) {
	a, err := DeriveLabeled([]byte("ikm"), LabelMsg, []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("first derivation: %v", err)
	}
	b, err := DeriveLabeled([]byte("ikm"), LabelMsg, []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the same inputs produced different outputs")
	}
}

func TestAdvanceChain(t *testing.T) {
	ck := bytes.Repeat([]byte{0x11}, KeySize)

	next, err := AdvanceChain(ck)
	if err != nil {
		t.Fatalf("AdvanceChain: %v", err)
	}
	if len(next) != KeySize {
		t.Fatalf("chain step returned %d bytes, want %d", len(next), KeySize)
	}
	if bytes.Equal(next, ck) {
		t.Fatal("chain step returned the input unchanged; the ratchet would never advance")
	}

	// Determinism is required: the receiver replays the same chain locally.
	again, err := AdvanceChain(ck)
	if err != nil {
		t.Fatalf("AdvanceChain (repeat): %v", err)
	}
	if !bytes.Equal(next, again) {
		t.Fatal("chain advance is not deterministic")
	}

	// The chain must not be reversible: two different keys must not collide.
	other, err := AdvanceChain(bytes.Repeat([]byte{0x22}, KeySize))
	if err != nil {
		t.Fatalf("AdvanceChain (other): %v", err)
	}
	if bytes.Equal(next, other) {
		t.Fatal("different chain keys produced the same next key")
	}
}

func TestAdvanceChainRejectsEmptyKey(t *testing.T) {
	if _, err := AdvanceChain(nil); err == nil {
		t.Fatal("expected an error for an empty chain key")
	}
}

// TestDeriveMessageKeyDirectionSeparation is the reflection attack test.
//
// If A->B and B->A keys for the same counter were equal, an attacker could
// reflect a victim's own ciphertext back at them and have it accepted as a
// valid inbound message.
func TestDeriveMessageKeyDirectionSeparation(t *testing.T) {
	ck := bytes.Repeat([]byte{0x33}, KeySize)

	ab, err := DeriveMessageKey(ck, DirAToB, 7)
	if err != nil {
		t.Fatalf("A->B derivation: %v", err)
	}
	defer ab.Zero()

	ba, err := DeriveMessageKey(ck, DirBToA, 7)
	if err != nil {
		t.Fatalf("B->A derivation: %v", err)
	}
	defer ba.Zero()

	if ab.Key == ba.Key {
		t.Fatal("both directions derived the same key for the same counter: reflection is possible")
	}
	if ab.Nonce == ba.Nonce {
		t.Fatal("both directions derived the same nonce for the same counter")
	}
}

func TestDeriveMessageKeyVariesWithCounter(t *testing.T) {
	ck := bytes.Repeat([]byte{0x44}, KeySize)

	base, err := DeriveMessageKey(ck, DirAToB, 0)
	if err != nil {
		t.Fatalf("counter 0: %v", err)
	}
	defer base.Zero()

	later, err := DeriveMessageKey(ck, DirAToB, 1)
	if err != nil {
		t.Fatalf("counter 1: %v", err)
	}
	defer later.Zero()

	if base.Key == later.Key {
		t.Fatal("counter did not affect the message key; nonce reuse would follow")
	}
	if base.Nonce == later.Nonce {
		t.Fatal("counter did not affect the nonce")
	}
}

// TestMessageKeyNonceWidths checks the truncation rule that lets one fixed-width
// derivation serve profiles with different nonce sizes.
//
// The content profile deliberately does NOT enter the key derivation, because a
// receiver caching keys for skipped messages cannot know the profile of a message
// it has not seen. The profile travels in the authenticated header instead; the
// consequence checked here is that the derived 24-byte nonce buffer must present
// the right width for each profile.
func TestMessageKeyNonceWidths(t *testing.T) {
	ck := bytes.Repeat([]byte{0x55}, KeySize)

	mk, err := DeriveMessageKey(ck, DirAToB, 0)
	if err != nil {
		t.Fatalf("DeriveMessageKey: %v", err)
	}
	defer mk.Zero()

	for _, p := range AllProfiles() {
		got := len(mk.NonceFor(p))
		want := p.NonceSize()
		if got != want {
			t.Errorf("profile %s: nonce width %d, want %d", p, got, want)
		}
	}

	// The 12-byte and 24-byte views must be prefixes of the same buffer, which is
	// safe because ChaCha20 and XChaCha20 use different nonce constructions.
	if !bytes.Equal(mk.NonceFor(ProfileText), mk.Nonce[:NonceSize]) {
		t.Fatal("short nonce is not the prefix of the derived buffer")
	}
	if !bytes.Equal(mk.NonceFor(ProfileFile), mk.Nonce[:XNonceSize]) {
		t.Fatal("extended nonce is not the full derived buffer")
	}
}

// TestLexSortIsRoleIndependent is the test for the LEXSORT design choice: the
// handshake must derive the same material no matter which side believes it is
// the initiator.
func TestLexSortIsRoleIndependent(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := []byte{0x00, 0x09}
	c := []byte{0xff}

	fromInitiator := LexSort(a, b, c)
	fromResponder := LexSort(c, b, a)

	for i := range fromInitiator {
		if !bytes.Equal(fromInitiator[i], fromResponder[i]) {
			t.Fatalf("LEXSORT is role dependent at index %d", i)
		}
	}
	if !bytes.Equal(fromInitiator[0], b) {
		t.Fatalf("expected the smallest input first, got %x", fromInitiator[0])
	}
}

func TestLexSortDoesNotMutateInput(t *testing.T) {
	a := []byte{0x05}
	b := []byte{0x01}
	in := [][]byte{a, b}

	LexSort(in...)

	if !bytes.Equal(in[0], a) || !bytes.Equal(in[1], b) {
		t.Fatal("LexSort mutated the caller's slice")
	}
}

func TestIdentityDigestBindsTranscript(t *testing.T) {
	idA := []byte("identity-a")
	idB := []byte("identity-b")

	base := IdentityDigest(WireVersion, idA, idB)
	if len(base) != 32 {
		t.Fatalf("digest is %d bytes, want 32", len(base))
	}

	// Order independence: both peers must compute the same value.
	if !bytes.Equal(base, IdentityDigest(WireVersion, idB, idA)) {
		t.Fatal("transcript digest depends on argument order")
	}

	// A version downgrade must change the digest, otherwise an attacker could
	// substitute an older protocol revision unnoticed.
	if bytes.Equal(base, IdentityDigest(0x00, idA, idB)) {
		t.Fatal("transcript digest does not bind the protocol version")
	}

	// Substituting an identity key must change the digest.
	if bytes.Equal(base, IdentityDigest(WireVersion, idA, []byte("identity-c"))) {
		t.Fatal("transcript digest does not bind the identity keys")
	}
}

// TestSafetyNumber is a usability-critical property: both users must see the
// same 60 digits, or verification is impossible.
func TestSafetyNumber(t *testing.T) {
	idA := []byte("identity-a")
	idB := []byte("identity-b")

	ab := SafetyNumber(idA, idB)
	ba := SafetyNumber(idB, idA)

	if !bytes.Equal(ab, ba) {
		t.Fatal("the two users would see different safety numbers")
	}
	if len(ab) != SafetyNumberSize {
		t.Fatalf("safety number is %d bytes, want %d", len(ab), SafetyNumberSize)
	}
	if bytes.Equal(ab, SafetyNumber(idA, []byte("identity-c"))) {
		t.Fatal("safety number does not depend on the peer identity")
	}
}

func TestAllLabelsAreWellFormed(t *testing.T) {
	seen := make(map[string]bool)
	for _, l := range AllLabels() {
		if l == "" {
			t.Fatal("found an empty label")
		}
		if !strings.HasPrefix(l, "SCS1/") {
			t.Fatalf("label %q does not use the SCS1/ namespace", l)
		}
		if !strings.HasSuffix(l, "/v1") {
			t.Fatalf("label %q is not version tagged", l)
		}
		if seen[l] {
			t.Fatalf("duplicate label %q", l)
		}
		seen[l] = true
	}
}
