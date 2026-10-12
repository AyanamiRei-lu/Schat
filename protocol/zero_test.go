package protocol

import (
	"bytes"
	"testing"
)

func TestZeroClearsBuffer(t *testing.T) {
	buf := bytes.Repeat([]byte{0xFF}, 64)
	Zero(buf)

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d is 0x%02x after Zero, want 0x00", i, b)
		}
	}
}

func TestZeroAll(t *testing.T) {
	a := bytes.Repeat([]byte{0xAA}, 32)
	b := bytes.Repeat([]byte{0xBB}, 32)
	c := bytes.Repeat([]byte{0xCC}, 32)

	ZeroAll(a, b, c)

	for name, buf := range map[string][]byte{"a": a, "b": b, "c": c} {
		for i, v := range buf {
			if v != 0 {
				t.Fatalf("buffer %s byte %d is 0x%02x after ZeroAll", name, i, v)
			}
		}
	}
}

// TestZeroHandlesEmptyAndNil makes sure scrubbing never panics on the degenerate
// cases, since it is called from deferred cleanup paths where a panic would
// replace a real error with a crash.
func TestZeroHandlesEmptyAndNil(t *testing.T) {
	Zero(nil)
	Zero([]byte{})
	ZeroAll()
	ZeroAll(nil, []byte{})
}

func TestMessageKeyZero(t *testing.T) {
	mk := &MessageKey{}
	for i := range mk.Key {
		mk.Key[i] = 0xFF
	}
	for i := range mk.Nonce {
		mk.Nonce[i] = 0xFF
	}

	mk.Zero()

	for i, b := range mk.Key {
		if b != 0 {
			t.Fatalf("key byte %d survived Zero", i)
		}
	}
	for i, b := range mk.Nonce {
		if b != 0 {
			t.Fatalf("nonce byte %d survived Zero", i)
		}
	}
}

func TestNilMessageKeyZeroIsSafe(t *testing.T) {
	var mk *MessageKey
	mk.Zero() // must not panic
}

func TestRootKeyZero(t *testing.T) {
	var rk RootKey
	for i := range rk {
		rk[i] = 0xFF
	}
	rk.Zero()
	for i, b := range rk {
		if b != 0 {
			t.Fatalf("root key byte %d survived Zero", i)
		}
	}
}

func TestIdentityKeyPairZero(t *testing.T) {
	kp := &IdentityKeyPair{
		SigningPrivate:   bytes.Repeat([]byte{0x01}, 64),
		SigningPublic:    bytes.Repeat([]byte{0x02}, 32),
		AgreementPrivate: bytes.Repeat([]byte{0x03}, 32),
		AgreementPublic:  bytes.Repeat([]byte{0x04}, 32),
	}

	kp.Zero()

	for i, b := range kp.SigningPrivate {
		if b != 0 {
			t.Fatalf("signing private byte %d survived Zero", i)
		}
	}
	for i, b := range kp.AgreementPrivate {
		if b != 0 {
			t.Fatalf("agreement private byte %d survived Zero", i)
		}
	}
	// Public keys are not secret and must be left intact.
	if kp.SigningPublic[0] != 0x02 {
		t.Fatal("Zero scrubbed a public key; that would break identity pinning")
	}
}

// TestSessionCloseScrubsKeyMaterial is the end-to-end scrub test: after a real
// session has exchanged messages, Close must leave no chain key, root key, cached
// message key or ratchet key reference behind.
//
// This replaced an earlier test of a RatchetState stub type that no longer exists
// now that the ratchet is implemented on the live Session.
func TestSessionCloseScrubsKeyMaterial(t *testing.T) {
	a, b := newTestSessionPair(t)

	for i := 0; i < 3; i++ {
		env, err := a.EncryptMessage([]byte("scrub me"), ProfileText)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		if _, err := b.DecryptMessage(env); err != nil {
			t.Fatalf("DecryptMessage: %v", err)
		}
	}

	// Create at least one skipped key in b's cache: hold one message back.
	held, err := a.EncryptMessage([]byte("held"), ProfileText)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	second, err := a.EncryptMessage([]byte("second"), ProfileText)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if _, err := b.DecryptMessage(second); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if b.SkippedKeyCount() != 1 {
		t.Fatalf("expected one cached skipped key, got %d", b.SkippedKeyCount())
	}
	_ = held

	a.Close()

	if a.dhSelfPriv != nil {
		t.Error("ratchet private key reference survived Close")
	}
	for i, v := range a.rootKey {
		if v != 0 {
			t.Fatalf("root key byte %d survived Close", i)
		}
	}
	for i, v := range a.ckSend {
		if v != 0 {
			t.Fatalf("sending chain byte %d survived Close", i)
		}
	}
	for i, v := range a.sessionAD {
		if v != 0 {
			t.Fatalf("session AD byte %d survived Close", i)
		}
	}

	b.Close()

	if b.SkippedKeyCount() != 0 {
		t.Error("cached skipped keys survived Close")
	}
	for i, v := range b.ckRecv {
		if v != 0 {
			t.Fatalf("receiving chain byte %d survived Close", i)
		}
	}
}

func TestNilSessionCloseIsSafe(t *testing.T) {
	var s *Session
	s.Close()
}

func TestPreKeyStoreZero(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	store, err := NewPreKeyStore(id, 4)
	if err != nil {
		t.Fatalf("NewPreKeyStore: %v", err)
	}
	if len(store.SignedPreKeyPrivate) != X25519KeySize {
		t.Fatal("test setup produced a wrongly sized signed prekey")
	}

	store.Zero()

	for i, v := range store.SignedPreKeyPrivate {
		if v != 0 {
			t.Fatalf("signed prekey byte %d survived Zero", i)
		}
	}
	if len(store.oneTimePrivates) != 0 {
		t.Fatal("one-time prekey privates survived Zero")
	}
}
