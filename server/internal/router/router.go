// Package router maps delivery tokens to live connections.
//
// The relay server knows only that "some connection is listening on mailbox T".
// It does not know which user owns T, where T's owner is, or who sent to T —
// the token rotates daily and carries no identity (SCHAT.md section 4.7). This
// package is the whole of that knowledge: two maps and a mutex.
//
// The second map, byConn, exists purely so that a dropped connection can be
// cleaned out of byToken in one pass. Without it, a flapping client would leak
// subscriptions until the server ran out of memory.
package router

import (
	"sort"
	"sync"
)

// Token is the 16-byte rotating delivery token.
type Token [16]byte

// ConnID identifies one live client connection.
type ConnID string

// Router tracks which connections are listening on which mailboxes.
type Router struct {
	mu sync.RWMutex

	byToken map[Token]map[ConnID]struct{}
	byConn  map[ConnID]map[Token]struct{}
}

// New creates an empty router.
func New() *Router {
	return &Router{
		byToken: make(map[Token]map[ConnID]struct{}),
		byConn:  make(map[ConnID]map[Token]struct{}),
	}
}

// Subscribe registers a connection as a listener for a mailbox.
//
// Subscribing twice is a no-op, so a client that re-sends its subscription
// after a reconnect cannot corrupt the count.
func (r *Router) Subscribe(t Token, id ConnID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conns, ok := r.byToken[t]
	if !ok {
		conns = make(map[ConnID]struct{})
		r.byToken[t] = conns
	}
	conns[id] = struct{}{}

	tokens, ok := r.byConn[id]
	if !ok {
		tokens = make(map[Token]struct{})
		r.byConn[id] = tokens
	}
	tokens[t] = struct{}{}
}

// Unsubscribe removes one mailbox binding for a connection.
func (r *Router) Unsubscribe(t Token, id ConnID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if conns, ok := r.byToken[t]; ok {
		delete(conns, id)
		if len(conns) == 0 {
			delete(r.byToken, t)
		}
	}
	if tokens, ok := r.byConn[id]; ok {
		delete(tokens, t)
		if len(tokens) == 0 {
			delete(r.byConn, id)
		}
	}
}

// RemoveConn drops every subscription belonging to a connection. It must be
// called when a connection closes.
func (r *Router) RemoveConn(id ConnID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tokens, ok := r.byConn[id]
	if !ok {
		return
	}
	for t := range tokens {
		if conns, ok := r.byToken[t]; ok {
			delete(conns, id)
			if len(conns) == 0 {
				delete(r.byToken, t)
			}
		}
	}
	delete(r.byConn, id)
}

// Online returns the connections currently listening on a mailbox.
//
// The result is sorted so that callers (and tests) see a deterministic order.
// An empty result means the recipient is offline; in live mode the relay then
// reports the envelope as undeliverable rather than storing it.
func (r *Router) Online(t Token) []ConnID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conns, ok := r.byToken[t]
	if !ok {
		return nil
	}
	out := make([]ConnID, 0, len(conns))
	for id := range conns {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsOnline reports whether anybody is listening on a mailbox.
func (r *Router) IsOnline(t Token) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byToken[t]) > 0
}

// Stats reports the number of mailboxes and connections currently tracked.
//
// The two values must stay consistent with each other; a growing gap between
// them would indicate a leak.
func (r *Router) Stats() (mailboxes int, conns int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byToken), len(r.byConn)
}
