// Package metrics holds the relay server's aggregate counters.
//
// Every value here is a count or a byte total. There is deliberately no way to
// record an identifier, an address or a payload: SCHAT.md section 7.2 promises
// that the server keeps no per-user record, and the cheapest way to keep that
// promise is to give the metrics layer nothing it could record.
package metrics

import (
	"sync/atomic"
	"time"
)

// Counters is the server's aggregate telemetry.
//
// Fields are atomic so that connection goroutines can update them without a
// mutex. Counters wrap rather than error on overflow, which is acceptable for
// monitoring.
type Counters struct {
	// startedAt is used to report uptime.
	startedAt time.Time

	// Current gauge values.
	liveConnections atomic.Int64
	liveMailboxes   atomic.Int64
	queuedEnvelopes atomic.Int64
	queuedBytes     atomic.Int64

	// Monotonic totals since start.
	totalConnections    atomic.Int64
	totalEnvelopes      atomic.Int64
	totalBytes          atomic.Int64
	deliveredEnvelopes  atomic.Int64
	droppedEnvelopes    atomic.Int64
	rejectedEnvelopes   atomic.Int64
	rejectedRateLimited atomic.Int64
}

// New creates a counter set with the uptime clock started.
func New() *Counters {
	return &Counters{startedAt: time.Now()}
}

// Uptime reports how long the process has been running.
func (c *Counters) Uptime() time.Duration { return time.Since(c.startedAt) }

// ConnectionOpened records a new client connection.
func (c *Counters) ConnectionOpened() {
	c.liveConnections.Add(1)
	c.totalConnections.Add(1)
}

// ConnectionClosed records a closed client connection.
func (c *Counters) ConnectionClosed() { c.liveConnections.Add(-1) }

// SetMailboxes records the current number of tracked mailboxes.
func (c *Counters) SetMailboxes(n int) { c.liveMailboxes.Store(int64(n)) }

// SetQueueDepth records the current queue occupancy.
func (c *Counters) SetQueueDepth(envelopes int, bytes int64) {
	c.queuedEnvelopes.Store(int64(envelopes))
	c.queuedBytes.Store(bytes)
}

// EnvelopeReceived records an accepted inbound envelope.
func (c *Counters) EnvelopeReceived(size int) {
	c.totalEnvelopes.Add(1)
	c.totalBytes.Add(int64(size))
}

// EnvelopeDelivered records an envelope handed to a live connection.
func (c *Counters) EnvelopeDelivered() { c.deliveredEnvelopes.Add(1) }

// EnvelopeDropped records an envelope discarded because the recipient was
// offline in live mode, or because a queue bound evicted it.
func (c *Counters) EnvelopeDropped() { c.droppedEnvelopes.Add(1) }

// EnvelopeRejected records an envelope refused for being malformed or oversized.
func (c *Counters) EnvelopeRejected() { c.rejectedEnvelopes.Add(1) }

// RateLimited records a connection throttled for exceeding its send rate.
func (c *Counters) RateLimited() { c.rejectedRateLimited.Add(1) }

// Snapshot is a point-in-time copy of the counters, safe to serialise as JSON.
type Snapshot struct {
	UptimeSeconds      float64 `json:"uptime_seconds"`
	LiveConnections    int64   `json:"live_connections"`
	LiveMailboxes      int64   `json:"live_mailboxes"`
	QueuedEnvelopes    int64   `json:"queued_envelopes"`
	QueuedBytes        int64   `json:"queued_bytes"`
	TotalConnections   int64   `json:"total_connections"`
	TotalEnvelopes     int64   `json:"total_envelopes"`
	TotalBytes         int64   `json:"total_bytes"`
	DeliveredEnvelopes int64   `json:"delivered_envelopes"`
	DroppedEnvelopes   int64   `json:"dropped_envelopes"`
	RejectedEnvelopes  int64   `json:"rejected_envelopes"`
	RateLimited        int64   `json:"rate_limited"`
}

// Snapshot copies the current values.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		UptimeSeconds:      c.Uptime().Seconds(),
		LiveConnections:    c.liveConnections.Load(),
		LiveMailboxes:      c.liveMailboxes.Load(),
		QueuedEnvelopes:    c.queuedEnvelopes.Load(),
		QueuedBytes:        c.queuedBytes.Load(),
		TotalConnections:   c.totalConnections.Load(),
		TotalEnvelopes:     c.totalEnvelopes.Load(),
		TotalBytes:         c.totalBytes.Load(),
		DeliveredEnvelopes: c.deliveredEnvelopes.Load(),
		DroppedEnvelopes:   c.droppedEnvelopes.Load(),
		RejectedEnvelopes:  c.rejectedEnvelopes.Load(),
		RateLimited:        c.rejectedRateLimited.Load(),
	}
}
