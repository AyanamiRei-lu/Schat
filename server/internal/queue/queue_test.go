package queue

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func testToken(b byte) Token {
	var t Token
	for i := range t {
		t[i] = b
	}
	return t
}

func mustQueue(t *testing.T, perToken int, ttl time.Duration, maxBytes int64) *Queue {
	t.Helper()
	q, err := New(perToken, ttl, maxBytes)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return q
}

func TestEnqueueDrainOrder(t *testing.T) {
	q := mustQueue(t, 10, time.Hour, 1<<20)
	tok := testToken(0x01)

	for i := 0; i < 3; i++ {
		if err := q.Enqueue(tok, []byte(fmt.Sprintf("m%d", i))); err != nil {
			t.Fatalf("Enqueue(%d): %v", i, err)
		}
	}

	got := q.Drain(tok)
	if len(got) != 3 {
		t.Fatalf("drained %d envelopes, want 3", len(got))
	}
	for i, want := range []string{"m0", "m1", "m2"} {
		if string(got[i]) != want {
			t.Errorf("position %d is %q, want %q (messages must arrive in order)", i, got[i], want)
		}
	}

	// Drain must be destructive: reading once must not leave a copy behind.
	if again := q.Drain(tok); again != nil {
		t.Fatalf("a second drain returned %d envelopes, want none", len(again))
	}
	if _, envelopes, bytes, _ := q.Stats(); envelopes != 0 || bytes != 0 {
		t.Fatalf("after draining everything the queue still reports %d envelopes / %d bytes", envelopes, bytes)
	}
}

func TestDrainUnknownTokenIsEmpty(t *testing.T) {
	q := mustQueue(t, 10, time.Hour, 1<<20)
	if got := q.Drain(testToken(0xff)); got != nil {
		t.Fatalf("draining an unknown mailbox returned %d envelopes", len(got))
	}
}

// TestPerMailboxBoundEvictsOldest is the anti-flood behaviour: a mailbox cannot
// grow without limit, and the newest messages survive.
func TestPerMailboxBoundEvictsOldest(t *testing.T) {
	q := mustQueue(t, 3, time.Hour, 1<<20)
	tok := testToken(0x02)

	for i := 0; i < 10; i++ {
		if err := q.Enqueue(tok, []byte(fmt.Sprintf("m%d", i))); err != nil {
			t.Fatalf("Enqueue(%d): %v", i, err)
		}
	}

	got := q.Drain(tok)
	if len(got) != 3 {
		t.Fatalf("mailbox holds %d envelopes, want the cap of 3", len(got))
	}
	for i, want := range []string{"m7", "m8", "m9"} {
		if string(got[i]) != want {
			t.Errorf("position %d is %q, want %q (the newest must survive)", i, got[i], want)
		}
	}

	if _, _, _, dropped := q.Stats(); dropped != 7 {
		t.Errorf("dropped count is %d, want 7", dropped)
	}
}

func TestEnqueueCopiesPayload(t *testing.T) {
	q := mustQueue(t, 10, time.Hour, 1<<20)
	tok := testToken(0x03)

	buf := []byte("original")
	if err := q.Enqueue(tok, buf); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Simulate a connection read loop reusing its buffer.
	copy(buf, "MUTATED!")

	got := q.Drain(tok)
	if len(got) != 1 || string(got[0]) != "original" {
		t.Fatalf("the queued payload was aliased to the caller's buffer: got %q", got[0])
	}
}

func TestGlobalBudgetIsEnforced(t *testing.T) {
	// Room for roughly two 100-byte payloads.
	q := mustQueue(t, 100, time.Hour, 250)

	if err := q.Enqueue(testToken(0x04), make([]byte, 100)); err != nil {
		t.Fatalf("first envelope should fit: %v", err)
	}
	if err := q.Enqueue(testToken(0x05), make([]byte, 100)); err != nil {
		t.Fatalf("second envelope should fit: %v", err)
	}
	err := q.Enqueue(testToken(0x06), make([]byte, 100))
	if !errors.Is(err, ErrGlobalFull) {
		t.Fatalf("expected ErrGlobalFull, got %v", err)
	}
}

func TestOversizedEnvelopeRejected(t *testing.T) {
	q := mustQueue(t, 10, time.Hour, 128)
	err := q.Enqueue(testToken(0x07), make([]byte, 200))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

// TestSweepExpiresMailboxes covers the TTL: an envelope that waits too long for
// an offline recipient disappears, in memory and in the accounting.
func TestSweepExpiresMailboxes(t *testing.T) {
	q := mustQueue(t, 10, time.Minute, 1<<20)

	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	current := base
	q.now = func() time.Time { return current }

	tok := testToken(0x08)
	if err := q.Enqueue(tok, []byte("stale")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Just inside the TTL: nothing may be dropped.
	current = base.Add(59 * time.Second)
	if dropped := q.Sweep(); dropped != 0 {
		t.Fatalf("swept %d envelopes before the TTL elapsed", dropped)
	}

	// Past the TTL: the envelope must go.
	current = base.Add(2 * time.Minute)
	if dropped := q.Sweep(); dropped != 1 {
		t.Fatalf("swept %d envelopes after the TTL elapsed, want 1", dropped)
	}

	if _, envelopes, bytes, _ := q.Stats(); envelopes != 0 || bytes != 0 {
		t.Fatalf("after expiry the queue reports %d envelopes / %d bytes, want 0/0", envelopes, bytes)
	}
	if got := q.Drain(tok); got != nil {
		t.Fatal("an expired envelope was still deliverable")
	}
}

func TestSweepKeepsFreshEntriesInMixedMailbox(t *testing.T) {
	q := mustQueue(t, 10, time.Minute, 1<<20)

	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	current := base
	q.now = func() time.Time { return current }

	tok := testToken(0x09)
	if err := q.Enqueue(tok, []byte("old")); err != nil {
		t.Fatalf("Enqueue(old): %v", err)
	}

	current = base.Add(50 * time.Second)
	if err := q.Enqueue(tok, []byte("new")); err != nil {
		t.Fatalf("Enqueue(new): %v", err)
	}

	current = base.Add(90 * time.Second)
	if dropped := q.Sweep(); dropped != 1 {
		t.Fatalf("swept %d envelopes, want exactly the expired one", dropped)
	}

	got := q.Drain(tok)
	if len(got) != 1 || string(got[0]) != "new" {
		t.Fatalf("the surviving envelope should be %q, got %v", "new", got)
	}
}

func TestClearRemovesEverything(t *testing.T) {
	q := mustQueue(t, 10, time.Hour, 1<<20)
	for i := byte(0); i < 5; i++ {
		if err := q.Enqueue(testToken(i), []byte("payload")); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	q.Clear()

	mailboxes, envelopes, bytes, _ := q.Stats()
	if mailboxes != 0 || envelopes != 0 || bytes != 0 {
		t.Fatalf("after Clear: %d mailboxes, %d envelopes, %d bytes", mailboxes, envelopes, bytes)
	}
}

func TestNewRejectsInvalidBounds(t *testing.T) {
	cases := []struct {
		name     string
		perToken int
		ttl      time.Duration
		maxBytes int64
	}{
		{"zero per-token", 0, time.Hour, 1 << 20},
		{"negative per-token", -1, time.Hour, 1 << 20},
		{"zero ttl", 10, 0, 1 << 20},
		{"negative ttl", 10, -time.Second, 1 << 20},
		{"zero bytes", 10, time.Hour, 0},
		{"negative bytes", 10, time.Hour, -1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.perToken, c.ttl, c.maxBytes); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
		})
	}
}

func TestQueueIsIndependentPerMailbox(t *testing.T) {
	q := mustQueue(t, 2, time.Hour, 1<<20)

	a, b := testToken(0xa1), testToken(0xb2)
	for i := 0; i < 5; i++ {
		if err := q.Enqueue(a, []byte("a")); err != nil {
			t.Fatalf("Enqueue(a): %v", err)
		}
	}
	if err := q.Enqueue(b, []byte("b")); err != nil {
		t.Fatalf("Enqueue(b): %v", err)
	}

	if got := q.Len(a); got != 2 {
		t.Fatalf("mailbox a holds %d, want its own cap of 2", got)
	}
	if got := q.Len(b); got != 1 {
		t.Fatalf("mailbox b holds %d, want 1 (flooding a must not evict b)", got)
	}
}

// TestConcurrentAccess exercises the queue under the race detector, which is how
// this package is expected to be run in CI.
func TestConcurrentAccess(t *testing.T) {
	q := mustQueue(t, 50, time.Hour, 1<<24)

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			tok := testToken(byte(w))
			for i := 0; i < 200; i++ {
				_ = q.Enqueue(tok, []byte("payload"))
				if i%7 == 0 {
					q.Drain(tok)
				}
				if i%11 == 0 {
					q.Sweep()
				}
				q.Len(tok)
				q.Stats()
			}
		}(w)
	}
	wg.Wait()

	// Accounting must remain consistent after the dust settles.
	_, envelopes, bytes, _ := q.Stats()
	if bytes < 0 || envelopes < 0 {
		t.Fatalf("accounting went negative: %d envelopes, %d bytes", envelopes, bytes)
	}
}
