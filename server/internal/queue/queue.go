// Package queue implements the bounded, in-memory, never-persisted mailbox the
// relay server uses in buffer mode.
//
// This package is where the zero-retention promise from SCHAT.md section 7 is
// enforced in code. Three properties matter and each is deliberate:
//
//  1. Everything lives in a map in RAM. There is no file handle, no database,
//     no mmap. Killing the process destroys the queue, and that is intended
//     behaviour rather than a limitation to be fixed later.
//  2. The queue is bounded twice: per mailbox, and globally. An attacker who
//     floods the server evicts old entries instead of causing an out-of-memory
//     kill, so a disk-less design does not turn into a trivial denial of
//     service.
//  3. Payloads are opaque bytes. This package never inspects them, and its API
//     offers no way to do so, because the server holds no key that could make
//     sense of them.
package queue

import (
	"errors"
	"sync"
	"time"
)

// Token is the 16-byte rotating delivery token identifying a mailbox
// (SCHAT.md section 4.7). It is unrelated to a user's identity.
type Token [16]byte

// Errors returned by the queue.
var (
	// ErrGlobalFull means the process-wide memory budget is exhausted. Callers
	// should reject the envelope with back-pressure rather than retrying.
	ErrGlobalFull = errors.New("queue: global memory budget exhausted")

	// ErrTooLarge means a single envelope exceeds the whole per-mailbox budget
	// and could therefore never be stored.
	ErrTooLarge = errors.New("queue: envelope exceeds the per-mailbox budget")

	// ErrInvalidConfig means the queue was constructed with unusable bounds.
	ErrInvalidConfig = errors.New("queue: invalid configuration")
)

// entry is one stored envelope.
type entry struct {
	payload []byte
	addedAt time.Time
}

// Queue is a bounded, TTL-expiring, in-memory store-and-forward buffer.
//
// All methods are safe for concurrent use.
type Queue struct {
	mu sync.Mutex

	maxPerToken int
	maxBytes    int64
	ttl         time.Duration

	bytes   int64
	buckets map[Token][]entry

	// now is injectable so that TTL behaviour can be tested without sleeping.
	now func() time.Time

	// dropped counts envelopes evicted by either bound, for metrics.
	dropped int64
}

// New creates a queue.
//
//	maxPerToken: maximum envelopes held for one mailbox (evicts oldest first)
//	ttl:         how long an envelope may wait for an offline recipient
//	maxBytes:    process-wide memory budget for queued payloads
func New(maxPerToken int, ttl time.Duration, maxBytes int64) (*Queue, error) {
	if maxPerToken <= 0 {
		return nil, ErrInvalidConfig
	}
	if ttl <= 0 {
		return nil, ErrInvalidConfig
	}
	if maxBytes <= 0 {
		return nil, ErrInvalidConfig
	}
	return &Queue{
		maxPerToken: maxPerToken,
		maxBytes:    maxBytes,
		ttl:         ttl,
		buckets:     make(map[Token][]entry),
		now:         time.Now,
	}, nil
}

// Enqueue stores a payload for a mailbox.
//
// When the mailbox is already at MaxPerToken the oldest envelope is evicted to
// make room. That is the right trade for a real-time chat relay: the newest
// messages are the ones a returning user cares about, and dropping the oldest
// keeps memory flat under a flood instead of refusing new traffic.
func (q *Queue) Enqueue(t Token, payload []byte) error {
	if int64(len(payload)) > q.maxBytes {
		return ErrTooLarge
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	incoming := int64(len(payload))
	if q.bytes+incoming > q.maxBytes {
		return ErrGlobalFull
	}

	bucket := q.buckets[t]

	// Evict oldest until the mailbox has room for one more.
	for len(bucket) >= q.maxPerToken {
		q.bytes -= int64(len(bucket[0].payload))
		bucket = bucket[1:]
		q.dropped++
	}

	// Copy the payload: the caller's buffer may be reused by the connection
	// read loop immediately after this call returns.
	stored := make([]byte, len(payload))
	copy(stored, payload)

	bucket = append(bucket, entry{payload: stored, addedAt: q.now()})
	q.buckets[t] = bucket
	q.bytes += incoming
	return nil
}

// Drain removes and returns every envelope held for a mailbox, oldest first.
//
// The returned slices are owned by the caller.
func (q *Queue) Drain(t Token) [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()

	bucket, ok := q.buckets[t]
	if !ok {
		return nil
	}
	delete(q.buckets, t)

	out := make([][]byte, 0, len(bucket))
	for _, e := range bucket {
		q.bytes -= int64(len(e.payload))
		out = append(out, e.payload)
	}
	return out
}

// Sweep removes envelopes that have outlived their TTL and returns how many were
// dropped.
//
// The caller is expected to run this periodically; the relay never relies on
// eviction alone to bound memory.
func (q *Queue) Sweep() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	cutoff := q.now().Add(-q.ttl)
	dropped := 0

	for t, bucket := range q.buckets {
		kept := bucket[:0]
		for _, e := range bucket {
			if e.addedAt.Before(cutoff) {
				q.bytes -= int64(len(e.payload))
				dropped++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(q.buckets, t)
			continue
		}
		q.buckets[t] = kept
	}

	q.dropped += int64(dropped)
	return dropped
}

// Stats reports the current queue occupancy.
func (q *Queue) Stats() (mailboxes int, envelopes int, bytes int64, dropped int64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, bucket := range q.buckets {
		envelopes += len(bucket)
	}
	return len(q.buckets), envelopes, q.bytes, q.dropped
}

// Len reports how many envelopes are held for one mailbox.
func (q *Queue) Len(t Token) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.buckets[t])
}

// Clear discards everything. It is used on shutdown so that a controlled stop
// leaves no user data behind even in a core dump.
func (q *Queue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	for t := range q.buckets {
		delete(q.buckets, t)
	}
	q.bytes = 0
}
