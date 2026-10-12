package protocol

import (
	"bytes"
	"errors"
	"testing"
)

// newTestSessionPair builds two live sessions that have completed SCS-HSK and can
// immediately exchange messages. It is the fixture for every ratchet test.
func newTestSessionPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	return newTestSessionPairWithOneTimePreKey(t, true)
}

func newTestSessionPairWithOneTimePreKey(t *testing.T, useOneTime bool) (*Session, *Session) {
	t.Helper()

	idA, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity A: %v", err)
	}
	idB, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generating identity B: %v", err)
	}

	store, err := NewPreKeyStore(idB, 5)
	if err != nil {
		t.Fatalf("NewPreKeyStore: %v", err)
	}

	oneTimeID := uint32(0)
	if useOneTime {
		oneTimeID = 1
	}
	bundle, err := store.Bundle(idB, oneTimeID)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	sessionA, init, err := EstablishSession(idA, bundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}

	sessionB, err := AcceptSession(idB, store, init)
	if err != nil {
		t.Fatalf("AcceptSession: %v", err)
	}

	return sessionA, sessionB
}

// --------------------------------------------------------------------------
// Identity keys and prekeys
// --------------------------------------------------------------------------

func TestGenerateIdentityProducesUsableKeys(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	if len(id.SigningPrivate) != Ed25519PrivateKeySize {
		t.Errorf("signing private key is %d bytes, want %d", len(id.SigningPrivate), Ed25519PrivateKeySize)
	}
	if len(id.SigningPublic) != Ed25519PublicKeySize {
		t.Errorf("signing public key is %d bytes, want %d", len(id.SigningPublic), Ed25519PublicKeySize)
	}
	if len(id.AgreementPrivate) != X25519KeySize {
		t.Errorf("agreement private key is %d bytes, want %d", len(id.AgreementPrivate), X25519KeySize)
	}
	if len(id.AgreementPublic) != X25519KeySize {
		t.Errorf("agreement public key is %d bytes, want %d", len(id.AgreementPublic), X25519KeySize)
	}

	// Two identities must never collide. crypto/rand is the only acceptable
	// source, and this is the cheapest way to catch a catastrophic regression to
	// math/rand or a fixed seed.
	other, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if bytes.Equal(id.AgreementPrivate, other.AgreementPrivate) {
		t.Fatal("two identities share an agreement private key")
	}
	if bytes.Equal(id.SigningPublic, other.SigningPublic) {
		t.Fatal("two identities share a signing public key")
	}
}

func TestIdentitySignAndVerify(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	msg := []byte("signed prekey material")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(id.SigningPublic, msg, sig); err != nil {
		t.Fatalf("Verify of a valid signature failed: %v", err)
	}

	// A modified message must not verify.
	if err := Verify(id.SigningPublic, []byte("signed prekey materiaL"), sig); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication for a modified message, got %v", err)
	}

	// A modified signature must not verify.
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0x01
	if err := Verify(id.SigningPublic, msg, tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication for a tampered signature, got %v", err)
	}

	// Another identity's key must not verify it.
	other, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := Verify(other.SigningPublic, msg, sig); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication under the wrong key, got %v", err)
	}
}

func TestVerifyRejectsMalformedInput(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sig, _ := id.Sign([]byte("m"))

	if err := Verify(make([]byte, 16), []byte("m"), sig); !errors.Is(err, ErrBadKeySize) {
		t.Errorf("expected ErrBadKeySize for a short public key, got %v", err)
	}
	if err := Verify(id.SigningPublic, []byte("m"), make([]byte, 16)); !errors.Is(err, ErrBadKeySize) {
		t.Errorf("expected ErrBadKeySize for a short signature, got %v", err)
	}
}

func TestPreKeyStoreBundle(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	store, err := NewPreKeyStore(id, 3)
	if err != nil {
		t.Fatalf("NewPreKeyStore: %v", err)
	}

	ids := store.OneTimePreKeyIDs()
	if len(ids) != 3 {
		t.Fatalf("pool holds %d prekeys, want 3", len(ids))
	}
	if ids[0] != 1 || ids[2] != 3 {
		t.Fatalf("prekey ids are not ascending: %v", ids)
	}

	bundle, err := store.Bundle(id, 2)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("bundle is not valid: %v", err)
	}
	// The published signature must verify, or no peer could start a session.
	if err := Verify(bundle.IdentitySigning, bundle.SignedPreKey, bundle.SignedPreKeySignature); err != nil {
		t.Fatalf("bundle signature does not verify: %v", err)
	}
	if bundle.OneTimePreKeyID != 2 {
		t.Fatalf("bundle names prekey %d, want 2", bundle.OneTimePreKeyID)
	}

	// A bundle without a one-time prekey is a legitimate degraded mode.
	noOTP, err := store.Bundle(id, 0)
	if err != nil {
		t.Fatalf("Bundle without a one-time prekey: %v", err)
	}
	if noOTP.OneTimePreKey != nil {
		t.Fatal("bundle without a one-time prekey still carries one")
	}
	if err := noOTP.Validate(); err != nil {
		t.Fatalf("degraded bundle is not valid: %v", err)
	}

	// Asking for an unknown prekey must fail rather than silently downgrade.
	if _, err := store.Bundle(id, 99); err == nil {
		t.Fatal("expected an error for an unknown one-time prekey id")
	}
}

// TestOneTimePreKeyIsSingleUse is the forward-secrecy property: the prekey must
// be gone after one use, so a second session cannot reuse the same DH input.
func TestOneTimePreKeyIsSingleUse(t *testing.T) {
	id, _ := GenerateIdentity()
	store, err := NewPreKeyStore(id, 2)
	if err != nil {
		t.Fatalf("NewPreKeyStore: %v", err)
	}

	if _, ok := store.ConsumeOneTimePreKey(1); !ok {
		t.Fatal("the first consumption of a prekey must succeed")
	}
	if _, ok := store.ConsumeOneTimePreKey(1); ok {
		t.Fatal("a one-time prekey was handed out twice")
	}
	if got := len(store.OneTimePreKeyIDs()); got != 1 {
		t.Fatalf("pool holds %d prekeys after one consumption, want 1", got)
	}
}

func TestNewPreKeyStoreRejectsBadCount(t *testing.T) {
	id, _ := GenerateIdentity()
	if _, err := NewPreKeyStore(id, -1); err == nil {
		t.Error("expected an error for a negative prekey count")
	}
	if _, err := NewPreKeyStore(id, 100000); err == nil {
		t.Error("expected an error for an unbounded prekey count")
	}
	if _, err := NewPreKeyStore(nil, 1); err == nil {
		t.Error("expected an error for a nil identity")
	}
}

// --------------------------------------------------------------------------
// Handshake
// --------------------------------------------------------------------------

func TestHandshakeInitRoundTrip(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	store, _ := NewPreKeyStore(idB, 2)
	bundle, _ := store.Bundle(idB, 1)

	_, init, err := EstablishSession(idA, bundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}

	wire := init.Marshal()
	if len(wire) != HandshakeInitSize {
		t.Fatalf("marshalled handshake init is %d bytes, want %d", len(wire), HandshakeInitSize)
	}

	out, err := UnmarshalHandshakeInit(wire)
	if err != nil {
		t.Fatalf("UnmarshalHandshakeInit: %v", err)
	}

	if !bytes.Equal(out.IdentitySigning, init.IdentitySigning) ||
		!bytes.Equal(out.IdentityAgreement, init.IdentityAgreement) ||
		!bytes.Equal(out.Ephemeral, init.Ephemeral) ||
		!bytes.Equal(out.RatchetPublic, init.RatchetPublic) {
		t.Fatal("a public value did not survive the handshake round trip")
	}
	if out.SignedPreKeyID != init.SignedPreKeyID || out.OneTimePreKeyID != init.OneTimePreKeyID {
		t.Fatal("a prekey id did not survive the handshake round trip")
	}
	if out.UsedOneTimePreKey != init.UsedOneTimePreKey {
		t.Fatal("the one-time prekey flag did not survive the round trip")
	}
}

func TestUnmarshalHandshakeInitRejectsBadInput(t *testing.T) {
	if _, err := UnmarshalHandshakeInit(make([]byte, HandshakeInitSize-1)); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}

	wire := make([]byte, HandshakeInitSize)
	wire[0] = 0x00
	if _, err := UnmarshalHandshakeInit(wire); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("expected ErrUnknownVersion, got %v", err)
	}
}

// TestHandshakeEstablishesWorkingSession is the core interoperability test: after
// the handshake, the two sides must be able to talk in both directions.
func TestHandshakeEstablishesWorkingSession(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	env, err := a.EncryptMessage([]byte("hello from A"), ProfileText)
	if err != nil {
		t.Fatalf("A encrypt: %v", err)
	}
	got, err := b.DecryptMessage(env)
	if err != nil {
		t.Fatalf("B decrypt: %v", err)
	}
	if string(got) != "hello from A" {
		t.Fatalf("B received %q", got)
	}

	env, err = b.EncryptMessage([]byte("hello from B"), ProfileText)
	if err != nil {
		t.Fatalf("B encrypt: %v", err)
	}
	got, err = a.DecryptMessage(env)
	if err != nil {
		t.Fatalf("A decrypt: %v", err)
	}
	if string(got) != "hello from B" {
		t.Fatalf("A received %q", got)
	}
}

// TestHandshakeDirectionBytesDiffer checks the anti-reflection property at the
// session level: the two peers must use different sending directions, and each
// must use the other's sending direction for receiving.
func TestHandshakeDirectionBytesDiffer(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	if a.sendDir == b.sendDir {
		t.Fatal("both peers send with the same direction byte")
	}
	if a.sendDir != b.recvDir {
		t.Fatalf("A sends with 0x%02x but B receives with 0x%02x", a.sendDir, b.recvDir)
	}
	if b.sendDir != a.recvDir {
		t.Fatalf("B sends with 0x%02x but A receives with 0x%02x", b.sendDir, a.recvDir)
	}
}

// TestHandshakeAdvertisesTheInitialRatchetKey checks the interop detail that lets
// the responder install its receiving chain immediately instead of waiting for the
// first ciphertext: the ratchet key in the handshake message must be the one the
// initiator's first frame will carry.
func TestHandshakeAdvertisesTheInitialRatchetKey(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	store, _ := NewPreKeyStore(idB, 2)
	bundle, _ := store.Bundle(idB, 1)

	sessionA, init, err := EstablishSession(idA, bundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	defer sessionA.Close()

	if !bytes.Equal(init.RatchetPublic, sessionA.RatchetPublic()) {
		t.Fatal("the handshake advertises a different ratchet key than the session uses")
	}

	// The responder must be able to receive the initiator's very first frame, which
	// is only true if AcceptSession derived the matching receiving chain.
	sessionB, err := AcceptSession(idB, store, init)
	if err != nil {
		t.Fatalf("AcceptSession: %v", err)
	}
	defer sessionB.Close()

	env, err := sessionA.EncryptMessage([]byte("first frame"), ProfileText)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := sessionB.DecryptMessage(env)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(got) != "first frame" {
		t.Fatalf("got %q", got)
	}
}

// TestHandshakeRejectsForgedSignedPreKey is the man-in-the-middle check on the
// prekey signature: substituting the signed prekey without the identity private
// key must be caught before any session is created.
func TestHandshakeRejectsForgedSignedPreKey(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	attacker, _ := GenerateIdentity()

	store, _ := NewPreKeyStore(idB, 2)
	bundle, _ := store.Bundle(idB, 1)

	// The attacker swaps in their own signed prekey but keeps B's identity key.
	attackerStore, _ := NewPreKeyStore(attacker, 1)
	bundle.SignedPreKey = attackerStore.SignedPreKeyPublic
	bundle.SignedPreKeySignature = attackerStore.SignedPreKeySignature

	if _, _, err := EstablishSession(idA, bundle); err == nil {
		t.Fatal("a handshake with a forged signed prekey must be rejected")
	}
}

func TestEstablishSessionRejectsMalformedBundle(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	store, _ := NewPreKeyStore(idB, 2)
	bundle, _ := store.Bundle(idB, 1)

	short := bundle
	short.IdentityAgreement = make([]byte, 16)
	if _, _, err := EstablishSession(idA, short); err == nil {
		t.Error("expected an error for a short identity agreement key")
	}

	noOneTime := bundle
	noOneTime.OneTimePreKey = make([]byte, 8)
	if _, _, err := EstablishSession(idA, noOneTime); err == nil {
		t.Error("expected an error for a wrongly sized one-time prekey")
	}

	if _, _, err := EstablishSession(nil, bundle); err == nil {
		t.Error("expected an error for a nil identity")
	}
}

// TestAcceptSessionRejectsReusedOneTimePreKey is the important one: replaying the
// same handshake initiation must not silently create a second session with the
// same DH inputs.
func TestAcceptSessionRejectsReusedOneTimePreKey(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	store, _ := NewPreKeyStore(idB, 2)
	bundle, _ := store.Bundle(idB, 1)

	_, init, err := EstablishSession(idA, bundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}

	first, err := AcceptSession(idB, store, init)
	if err != nil {
		t.Fatalf("first AcceptSession: %v", err)
	}
	defer first.Close()

	if _, err := AcceptSession(idB, store, init); err == nil {
		t.Fatal("a replayed handshake reused the same one-time prekey")
	}
}

func TestAcceptSessionRejectsWrongPreKeyID(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	store, _ := NewPreKeyStore(idB, 2)
	bundle, _ := store.Bundle(idB, 1)

	_, init, err := EstablishSession(idA, bundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	init.SignedPreKeyID = 99

	if _, err := AcceptSession(idB, store, init); err == nil {
		t.Fatal("expected an error when the handshake names an unknown signed prekey")
	}
}

// TestSessionWithoutOneTimePreKeyStillWorks confirms the documented degraded mode:
// no one-time prekey means no forward secrecy for the first message, not a broken
// session.
func TestSessionWithoutOneTimePreKeyStillWorks(t *testing.T) {
	a, b := newTestSessionPairWithOneTimePreKey(t, false)
	defer a.Close()
	defer b.Close()

	env, err := a.EncryptMessage([]byte("no one-time prekey here"), ProfileText)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if a.sendDir != DirAToB {
		t.Fatal("unexpected direction byte")
	}
	got, err := b.DecryptMessage(env)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(got) != "no one-time prekey here" {
		t.Fatalf("got %q", got)
	}
}

// TestHandshakeTranscriptBindsTheOneTimePreKey checks that the transcript really
// does cover the one-time prekey: if it did not, two different handshakes could
// derive the same root key.
func TestHandshakeTranscriptBindsTheOneTimePreKey(t *testing.T) {
	idA := bytes.Repeat([]byte{0x01}, X25519KeySize)
	idB := bytes.Repeat([]byte{0x02}, X25519KeySize)
	spk := bytes.Repeat([]byte{0x03}, X25519KeySize)

	withOTP := HandshakeTranscript(WireVersion, idA, idB, spk, bytes.Repeat([]byte{0x04}, X25519KeySize))

	if bytes.Equal(withOTP, HandshakeTranscript(WireVersion, idA, idB, spk, nil)) {
		t.Fatal("the transcript ignores the one-time prekey")
	}
	// Order independence: both peers must compute the same transcript.
	if !bytes.Equal(withOTP, HandshakeTranscript(WireVersion, idB, idA, spk, bytes.Repeat([]byte{0x04}, X25519KeySize))) {
		t.Fatal("the transcript depends on argument order")
	}
}
