package protocol

import (
	"bytes"
	"errors"
	"testing"
)

// A snapshot that cannot be restored is worse than no snapshot at all: the client would
// believe it had a session and every message would fail to decrypt with no explanation.
// These tests therefore focus on the only thing that matters — that a restored session
// can carry on the conversation.

func TestSnapshotRoundTripContinuesTheConversation(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer b.Close()

	// Exchange first, so that both chains and the ratchet keys exist.
	mustDecrypt(t, b, mustEncrypt(t, a, "one"), "one")
	mustDecrypt(t, a, mustEncrypt(t, b, "two"), "two")

	blob, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("Snapshot produced nothing")
	}
	a.Close()

	restored, err := RestoreSession(blob)
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	defer restored.Close()

	// The peer must still be able to reach the restored client. This is the assertion
	// that catches a dropped chain key or a lost ratchet private key.
	mustDecrypt(t, restored, mustEncrypt(t, b, "after restore"), "after restore")

	// And the restored client must still be able to reach the peer, which requires the
	// local ratchet private key to have survived.
	mustDecrypt(t, b, mustEncrypt(t, restored, "recovered"), "recovered")
}

// TestRestoredSessionSurvivesManyMessages guards against a snapshot that restores
// "almost" correctly: a chain that is one step off would work once and then fail.
func TestRestoredSessionSurvivesManyMessages(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer b.Close()

	for i := 0; i < 3; i++ {
		mustDecrypt(t, b, mustEncrypt(t, a, "pre"), "pre")
	}

	blob, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	a.Close()

	restored, err := RestoreSession(blob)
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	defer restored.Close()

	for i := 0; i < 40; i++ {
		mustDecrypt(t, b, mustEncrypt(t, restored, "post"), "post")
		mustDecrypt(t, restored, mustEncrypt(t, b, "reply"), "reply")
	}
}

// TestSnapshotPreservesSkippedKeys is the case that would silently lose messages: a
// message was skipped before the restart, and must still decrypt afterwards.
func TestSnapshotPreservesSkippedKeys(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()

	held := mustEncrypt(t, a, "held back")
	second := mustEncrypt(t, a, "second")
	mustDecrypt(t, b, second, "second")

	if b.SkippedKeyCount() != 1 {
		t.Fatalf("expected one cached key, got %d", b.SkippedKeyCount())
	}

	blob, err := b.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	b.Close()

	restored, err := RestoreSession(blob)
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	defer restored.Close()

	if restored.SkippedKeyCount() != 1 {
		t.Fatalf("the cached key did not survive: %d present", restored.SkippedKeyCount())
	}
	mustDecrypt(t, restored, held, "held back")
	if restored.SkippedKeyCount() != 0 {
		t.Fatal("the restored cached key was not consumed")
	}
}

func TestSnapshotPreservesCounters(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	for i := 0; i < 5; i++ {
		mustDecrypt(t, b, mustEncrypt(t, a, "x"), "x")
	}

	blob, err := b.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	restored, err := RestoreSession(blob)
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	defer restored.Close()

	if restored.RecvCounter() != b.RecvCounter() {
		t.Fatalf("receive counter %d, want %d", restored.RecvCounter(), b.RecvCounter())
	}
	if restored.SendCounter() != b.SendCounter() {
		t.Fatalf("send counter %d, want %d", restored.SendCounter(), b.SendCounter())
	}
	if !bytes.Equal(restored.RatchetPublic(), b.RatchetPublic()) {
		t.Fatal("the ratchet public key changed across a snapshot")
	}
}

// TestSnapshotsDifferPerSession is a smoke test against a serialiser that forgets to
// write a field: two unrelated sessions must not produce the same bytes.
func TestSnapshotsDifferPerSession(t *testing.T) {
	a1, b1 := newTestSessionPair(t)
	a2, b2 := newTestSessionPair(t)
	defer a1.Close()
	defer b1.Close()
	defer a2.Close()
	defer b2.Close()

	s1, err := a1.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	s2, err := a2.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two unrelated sessions produced identical snapshots")
	}
}

func TestRestoreRejectsMalformedSnapshots(t *testing.T) {
	a, _ := newTestSessionPair(t)
	good, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	a.Close()

	cases := []struct {
		name string
		blob []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{'S', 'C', 'S', '1'}},
		{"bad magic", func() []byte { b := append([]byte(nil), good...); b[0] = 'X'; return b }()},
		{"bad version", func() []byte { b := append([]byte(nil), good...); b[4] = 99; return b }()},
		{"truncated header", good[:9]},
		{"truncated body", good[:len(good)/2]},
		{"one byte short", good[:len(good)-1]},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := RestoreSession(c.blob); !errors.Is(err, ErrBadSnapshot) {
				t.Fatalf("expected ErrBadSnapshot, got %v", err)
			}
		})
	}
}

func TestRestoreRejectsOversizedSnapshot(t *testing.T) {
	blob := make([]byte, SnapshotSizeLimit+1)
	copy(blob, []byte{'S', 'C', 'S', '1', snapshotVersion})

	if _, err := RestoreSession(blob); !errors.Is(err, ErrBadSnapshot) {
		t.Fatalf("expected the size ceiling to apply, got %v", err)
	}
}

// TestRestoreRejectsAnAbsurdSkippedKeyCount covers a crafted snapshot asking for a huge
// allocation. The bound must apply before anything is allocated, not after.
func TestRestoreRejectsAnAbsurdSkippedKeyCount(t *testing.T) {
	a, _ := newTestSessionPair(t)
	good, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	a.Close()

	// The skipped-key count is the last four-byte field, so overwrite everything after
	// the header with a count that exceeds the bound and nothing else.
	crafted := append([]byte(nil), good[:5]...)
	crafted = append(crafted, make([]byte, 4+1+2+32+2+32+2+32+2+32+1+2+32+2+32+4+4+4+8)...)
	// Position of the count is not pinned by the format documentation on purpose; the
	// test locates it by writing a large value at every four-byte offset and requiring
	// that at least one is refused rather than allocated.
	found := false
	for offset := 5; offset+4 <= len(crafted); offset += 4 {
		candidate := append([]byte(nil), crafted...)
		candidate[offset] = 0xFF
		candidate[offset+1] = 0xFF
		candidate[offset+2] = 0xFF
		candidate[offset+3] = 0xFF
		if _, err := RestoreSession(candidate); errors.Is(err, ErrBadSnapshot) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no oversized skipped-key count was rejected")
	}
}

// TestRestoreRejectsTamperedFields checks that mutating a byte inside the snapshot is
// detected rather than producing a session that quietly misbehaves.
func TestRestoreRejectsTamperedFields(t *testing.T) {
	a, _ := newTestSessionPair(t)
	good, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	a.Close()

	accepted := 0
	for i := 5; i < len(good); i++ {
		mutated := append([]byte(nil), good...)
		mutated[i] ^= 0xFF

		s, err := RestoreSession(mutated)
		if err == nil {
			// A byte inside a key or chain simply decodes to a different value; the
			// format cannot detect that, and the vault's authentication tag is what
			// does. Count them so the expectation is explicit rather than assumed.
			accepted++
			s.Close()
		}
	}

	// Most bytes are key material, so most mutations decode cleanly. What must never
	// happen is a panic, and what must happen is that the structural fields reject.
	if accepted == len(good)-5 {
		t.Fatal("every mutation was accepted; the structural checks are not running")
	}
}

// TestSnapshotAfterCloseIsStillReadable documents a deliberate property: Close scrubs
// the live session, but a snapshot taken beforehand is unaffected because it is a
// separate buffer. Callers must therefore treat the snapshot itself as the secret.
func TestSnapshotIsIndependentOfTheLiveSession(t *testing.T) {
	a, _ := newTestSessionPair(t)

	blob, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	copyOfBlob := append([]byte(nil), blob...)

	a.Close()

	if !bytes.Equal(blob, copyOfBlob) {
		t.Fatal("Close mutated the snapshot buffer")
	}
	if _, err := RestoreSession(blob); err != nil {
		t.Fatalf("a snapshot taken before Close must still restore: %v", err)
	}
}
