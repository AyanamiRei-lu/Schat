package router

import (
	"sync"
	"testing"
)

func tok(b byte) Token {
	var t Token
	for i := range t {
		t[i] = b
	}
	return t
}

func TestSubscribeAndOnline(t *testing.T) {
	r := New()
	t1 := tok(0x01)

	if r.IsOnline(t1) {
		t.Fatal("a fresh router reported a mailbox as online")
	}

	r.Subscribe(t1, "conn-a")

	if !r.IsOnline(t1) {
		t.Fatal("mailbox should be online after subscribing")
	}
	got := r.Online(t1)
	if len(got) != 1 || got[0] != "conn-a" {
		t.Fatalf("got %v, want [conn-a]", got)
	}
}

func TestSubscribeIsIdempotent(t *testing.T) {
	r := New()
	t1 := tok(0x02)

	for i := 0; i < 5; i++ {
		r.Subscribe(t1, "conn-a")
	}

	if got := r.Online(t1); len(got) != 1 {
		t.Fatalf("duplicate subscriptions produced %d entries, want 1", len(got))
	}
	mailboxes, conns := r.Stats()
	if mailboxes != 1 || conns != 1 {
		t.Fatalf("stats are %d mailboxes / %d conns, want 1/1", mailboxes, conns)
	}
}

func TestUnsubscribe(t *testing.T) {
	r := New()
	t1 := tok(0x03)

	r.Subscribe(t1, "conn-a")
	r.Unsubscribe(t1, "conn-a")

	if r.IsOnline(t1) {
		t.Fatal("mailbox still online after unsubscribing")
	}
	if mailboxes, conns := r.Stats(); mailboxes != 0 || conns != 0 {
		t.Fatalf("stats are %d/%d after unsubscribe, want 0/0", mailboxes, conns)
	}
}

// TestRemoveConnCleansBothMaps is the leak test. A connection that closes without
// unsubscribing must not leave dangling entries behind.
func TestRemoveConnCleansBothMaps(t *testing.T) {
	r := New()

	r.Subscribe(tok(0x04), "conn-a")
	r.Subscribe(tok(0x05), "conn-a")
	r.Subscribe(tok(0x06), "conn-a")
	r.Subscribe(tok(0x04), "conn-b")

	r.RemoveConn("conn-a")

	// conn-b is still listening on 0x04.
	if got := r.Online(tok(0x04)); len(got) != 1 || got[0] != "conn-b" {
		t.Fatalf("mailbox 0x04 should still have conn-b, got %v", got)
	}
	if r.IsOnline(tok(0x05)) || r.IsOnline(tok(0x06)) {
		t.Fatal("mailboxes used only by the removed connection are still online")
	}

	mailboxes, conns := r.Stats()
	if mailboxes != 1 || conns != 1 {
		t.Fatalf("stats are %d mailboxes / %d conns, want 1/1 (a leak would show a larger number)", mailboxes, conns)
	}
}

func TestRemoveUnknownConnIsSafe(t *testing.T) {
	r := New()
	r.RemoveConn("never-seen") // must not panic
	if mailboxes, conns := r.Stats(); mailboxes != 0 || conns != 0 {
		t.Fatalf("stats changed to %d/%d", mailboxes, conns)
	}
}

func TestOnlineIsDeterministicallyOrdered(t *testing.T) {
	r := New()
	t1 := tok(0x07)

	for _, id := range []ConnID{"conn-c", "conn-a", "conn-b"} {
		r.Subscribe(t1, id)
	}

	got := r.Online(t1)
	want := []ConnID{"conn-a", "conn-b", "conn-c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order is %v, want %v", got, want)
		}
	}
}

func TestOnlineReturnsCopy(t *testing.T) {
	r := New()
	t1 := tok(0x08)
	r.Subscribe(t1, "conn-a")

	got := r.Online(t1)
	got[0] = "mutated"

	if again := r.Online(t1); again[0] != "conn-a" {
		t.Fatal("Online leaked internal state; callers can corrupt the router")
	}
}

func TestMultipleConnectionsPerMailbox(t *testing.T) {
	// A user with two devices subscribed to the same mailbox.
	r := New()
	t1 := tok(0x09)

	r.Subscribe(t1, "phone")
	r.Subscribe(t1, "tablet")

	if got := r.Online(t1); len(got) != 2 {
		t.Fatalf("got %d connections, want 2", len(got))
	}

	r.Unsubscribe(t1, "tablet")

	if got := r.Online(t1); len(got) != 1 || got[0] != "phone" {
		t.Fatalf("after unsubscribing the tablet, got %v", got)
	}
}

func TestConcurrentAccess(t *testing.T) {
	r := New()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := ConnID(string(rune('a' + w)))
			for i := 0; i < 200; i++ {
				t1 := tok(byte(i % 16))
				r.Subscribe(t1, id)
				r.Online(t1)
				r.IsOnline(t1)
				if i%5 == 0 {
					r.Unsubscribe(t1, id)
				}
				if i%13 == 0 {
					r.RemoveConn(id)
				}
				r.Stats()
			}
		}(w)
	}
	wg.Wait()

	// After every connection has been removed, the router must be empty again.
	for w := 0; w < 8; w++ {
		r.RemoveConn(ConnID(string(rune('a' + w))))
	}
	if mailboxes, conns := r.Stats(); mailboxes != 0 || conns != 0 {
		t.Fatalf("router leaked: %d mailboxes / %d conns remain", mailboxes, conns)
	}
}
