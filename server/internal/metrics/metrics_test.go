package metrics

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestCountersTrackConnections(t *testing.T) {
	c := New()

	if got := c.Snapshot().LiveConnections; got != 0 {
		t.Fatalf("a fresh counter set reports %d live connections", got)
	}

	c.ConnectionOpened()
	c.ConnectionOpened()
	c.ConnectionClosed()

	snap := c.Snapshot()
	if snap.LiveConnections != 1 {
		t.Errorf("live connections = %d, want 1", snap.LiveConnections)
	}
	if snap.TotalConnections != 2 {
		t.Errorf("total connections = %d, want 2", snap.TotalConnections)
	}
}

func TestCountersTrackEnvelopes(t *testing.T) {
	c := New()

	c.EnvelopeReceived(100)
	c.EnvelopeReceived(250)
	c.EnvelopeDelivered()
	c.EnvelopeDropped()
	c.EnvelopeRejected()
	c.RateLimited()

	snap := c.Snapshot()
	if snap.TotalEnvelopes != 2 {
		t.Errorf("total envelopes = %d, want 2", snap.TotalEnvelopes)
	}
	if snap.TotalBytes != 350 {
		t.Errorf("total bytes = %d, want 350", snap.TotalBytes)
	}
	if snap.DeliveredEnvelopes != 1 || snap.DroppedEnvelopes != 1 {
		t.Errorf("delivered/dropped = %d/%d, want 1/1",
			snap.DeliveredEnvelopes, snap.DroppedEnvelopes)
	}
	if snap.RejectedEnvelopes != 1 || snap.RateLimited != 1 {
		t.Errorf("rejected/rate-limited = %d/%d, want 1/1",
			snap.RejectedEnvelopes, snap.RateLimited)
	}
}

func TestGaugesAreSetNotAccumulated(t *testing.T) {
	c := New()

	c.SetMailboxes(5)
	c.SetMailboxes(3)
	if got := c.Snapshot().LiveMailboxes; got != 3 {
		t.Fatalf("mailboxes = %d, want the latest value 3", got)
	}

	c.SetQueueDepth(10, 2048)
	c.SetQueueDepth(4, 512)
	snap := c.Snapshot()
	if snap.QueuedEnvelopes != 4 || snap.QueuedBytes != 512 {
		t.Fatalf("queue gauges = %d/%d, want 4/512", snap.QueuedEnvelopes, snap.QueuedBytes)
	}
}

// TestUptimeAdvances checks the uptime clock.
//
// The first assertion is deliberately >= rather than >: time.Now has coarse
// enough resolution on some platforms that two calls in immediate succession can
// return the same reading, and an uptime of exactly zero is a legitimate answer
// for a counter set that was created microseconds ago. Only after real time has
// passed is a strictly positive reading meaningful.
func TestUptimeAdvances(t *testing.T) {
	c := New()

	if c.Uptime() < 0 {
		t.Fatal("uptime must never be negative")
	}

	time.Sleep(20 * time.Millisecond)

	if c.Uptime() <= 0 {
		t.Fatal("uptime did not advance after 20ms")
	}
	if c.Snapshot().UptimeSeconds <= 0 {
		t.Fatal("the snapshot must report a positive uptime after real time has passed")
	}
}

func TestSnapshotIsSerialisable(t *testing.T) {
	c := New()
	c.ConnectionOpened()
	c.EnvelopeReceived(42)

	raw, err := json.Marshal(c.Snapshot())
	if err != nil {
		t.Fatalf("Snapshot must be JSON serialisable: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("marshalled snapshot is empty")
	}
}

// TestCountersAreRaceFree is intended to be run with -race in CI; the metrics
// layer is written from many connection goroutines at once.
func TestCountersAreRaceFree(t *testing.T) {
	c := New()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.ConnectionOpened()
				c.EnvelopeReceived(64)
				c.EnvelopeDelivered()
				c.Snapshot()
				c.ConnectionClosed()
			}
		}()
	}
	wg.Wait()

	snap := c.Snapshot()
	if snap.LiveConnections != 0 {
		t.Errorf("live connections = %d, want 0 once every connection closed", snap.LiveConnections)
	}
	if snap.TotalConnections != 4000 {
		t.Errorf("total connections = %d, want 4000", snap.TotalConnections)
	}
}
