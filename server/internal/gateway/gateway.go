// Package gateway terminates client connections and moves opaque envelopes
// between them.
//
// # The wire protocol
//
// Client to server, TEXT frames carry JSON control messages:
//
//	{"t":"sub","tokens":["<32 hex chars>", ...]}   subscribe to mailboxes
//	{"t":"unsub","tokens":[...]}                   unsubscribe
//	{"t":"hb"}                                     application heartbeat
//
// Client to server, BINARY frames carry one envelope:
//
//	token (16 bytes) || SCS-1 frame
//
// The server reads exactly the first sixteen bytes, which is all routing needs,
// and never inspects the rest. That is enforced by the code shape rather than by
// discipline: nothing in this package ever indexes past that offset.
//
// Server to client, BINARY frames carry an envelope back, byte for byte identical
// to what was deposited, including the token, so the recipient knows which of its
// mailboxes the message arrived on.
//
// Server to client, TEXT frames carry JSON replies:
//
//	{"t":"ok"}                     subscription or unsubscription accepted
//	{"t":"hb"}                     heartbeat reply
//	{"t":"delivered","n":2}         forwarded to n live connections
//	{"t":"queued"}                 held in memory for a currently offline mailbox
//	{"t":"offline"}                live mode: nobody is listening, nothing stored
//	{"t":"err","m":"..."}          the frame was rejected
//
// # Why the design looks like this
//
// A delivery token is a capability. A client that holds one may deposit into that
// mailbox, and the server learns nothing about who is sending or who owns the
// mailbox (SCHAT.md section 4.7). There is no authentication step because there is
// nothing to authenticate: the token is the whole authority, it rotates daily, and
// it carries no identity.
//
// In live mode an envelope for an offline mailbox is refused rather than held, and
// the sender is told so. Silence would let a user believe a message was delivered
// when it was dropped, which is the single most damaging thing a messenger can do.
package gateway

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/schat/schat/server/internal/config"
	"github.com/schat/schat/server/internal/metrics"
	"github.com/schat/schat/server/internal/queue"
	"github.com/schat/schat/server/internal/router"
	"github.com/schat/schat/server/internal/ws"
)

// TokenSize is the length of a delivery token.
//
// It is duplicated here rather than imported from the protocol module. That is
// deliberate: server/go.mod forbids importing the protocol core, so that the
// relay binary contains no code capable of reading an envelope. A single shared
// integer is not worth breaking that guarantee, and a test asserts the two agree.
const TokenSize = 16

// Control message types.
const (
	TypeSubscribe   = "sub"
	TypeUnsubscribe = "unsub"
	TypeHeartbeat   = "hb"
)

// Server reply types.
const (
	ReplyOK        = "ok"
	ReplyHeartbeat = "hb"
	ReplyDelivered = "delivered"
	ReplyQueued    = "queued"
	ReplyOffline   = "offline"
	ReplyError     = "err"
)

// controlMessage is a client-to-server JSON message.
type controlMessage struct {
	Type   string   `json:"t"`
	Tokens []string `json:"tokens,omitempty"`
}

// serverMessage is a server-to-client JSON reply.
type serverMessage struct {
	Type    string `json:"t"`
	Message string `json:"m,omitempty"`
	Count   int    `json:"n,omitempty"`
}

// Gateway owns the connection-facing state of the relay.
type Gateway struct {
	cfg     config.Config
	router  *router.Router
	queue   *queue.Queue
	metrics *metrics.Counters
	log     *slog.Logger

	// conns maps a connection id to its live connection, so that an envelope can
	// be written to whoever is listening on a mailbox.
	connsMu sync.RWMutex
	conns   map[router.ConnID]*ws.Conn

	nextConnID atomic.Uint64
}

// New builds a gateway. The queue may be nil in live mode, where nothing is ever
// stored.
func New(cfg config.Config, r *router.Router, q *queue.Queue, m *metrics.Counters, log *slog.Logger) *Gateway {
	return &Gateway{
		cfg:     cfg,
		router:  r,
		queue:   q,
		metrics: m,
		log:     log,
		conns:   make(map[router.ConnID]*ws.Conn),
	}
}

// wsOptions derives the WebSocket options from the server configuration.
func (g *Gateway) wsOptions() ws.Options {
	max := g.cfg.Limits.MaxEnvelopeSize
	if max <= 0 {
		max = 8 << 20
	}
	return ws.Options{
		// The envelope cap plus the 16-byte token prefix, and a little slack for
		// the JSON control channel.
		MaxMessageSize: max + 1024,
		ReadTimeout:    g.cfg.Limits.IdleTimeout,
		WriteTimeout:   30 * time.Second,
		Subprotocols:   []string{"schat.v1"},
	}
}

// ServeWS handles the client connection endpoint.
func (g *Gateway) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Upgrade(w, r, g.wsOptions())
	if err != nil {
		switch {
		case errors.Is(err, ws.ErrNotWebSocket):
			g.log.Warn("rejected a malformed websocket handshake", "remote", r.RemoteAddr)
			http.Error(w, "bad websocket handshake", http.StatusBadRequest)
		case errors.Is(err, ws.ErrHijackUnsupported):
			g.log.Error("cannot upgrade: the connection is not HTTP/1.1", "remote", r.RemoteAddr)
			http.Error(w, "websocket requires HTTP/1.1", http.StatusInternalServerError)
		default:
			// The connection was already taken over or has failed; there is no
			// HTTP response left to write.
			g.log.Warn("websocket upgrade failed", "remote", r.RemoteAddr, "err", err)
		}
		return
	}

	id := router.ConnID(fmt.Sprintf("c%d", g.nextConnID.Add(1)))
	g.registerConn(id, conn)
	g.metrics.ConnectionOpened()

	g.log.Debug("client connected", "id", id, "remote", conn.RemoteAddr().String())

	defer func() {
		g.unregisterConn(id)
		g.metrics.ConnectionClosed()
		g.metrics.SetMailboxes(g.mailboxCount())
		_ = conn.CloseNow()
		g.log.Debug("client disconnected", "id", id)
	}()

	g.serve(conn, id)
}

// serve reads messages until the peer goes away.
func (g *Gateway) serve(conn *ws.Conn, id router.ConnID) {
	limiter := newRateLimiter(g.cfg.Limits.SendRatePerSec)

	for {
		opcode, payload, err := conn.ReadMessage()
		if err != nil {
			// A frame refused by the transport layer never reaches handleEnvelope,
			// so the envelope counters would stay silent about it. An operator
			// watching for abuse needs to see oversized frames, so they are counted
			// here instead. Every other error is an ordinary disconnect.
			if errors.Is(err, ws.ErrMessageTooLarge) {
				g.metrics.EnvelopeRejected()
			}
			return
		}

		if !limiter.allow(time.Now()) {
			g.metrics.RateLimited()
			if err := conn.WriteText(marshalServerMessage(serverMessage{
				Type:    ReplyError,
				Message: "rate limit exceeded",
			})); err != nil {
				return
			}
			continue
		}

		switch opcode {
		case ws.OpText:
			if err := g.handleControl(conn, id, payload); err != nil {
				return
			}
		case ws.OpBinary:
			if err := g.handleEnvelope(conn, payload); err != nil {
				return
			}
		default:
			// ReadMessage only ever yields text or binary, so this is unreachable.
			return
		}
	}
}

// handleControl processes a JSON control message.
func (g *Gateway) handleControl(conn *ws.Conn, id router.ConnID, payload []byte) error {
	var msg controlMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return g.replyError(conn, "malformed control message")
	}

	switch msg.Type {
	case TypeSubscribe:
		tokens, err := parseTokens(msg.Tokens)
		if err != nil {
			return g.replyError(conn, err.Error())
		}
		for _, t := range tokens {
			g.router.Subscribe(t, id)
		}
		g.metrics.SetMailboxes(g.mailboxCount())

		// Collect anything held while this client was away. Subscribing first means
		// a message arriving during this window is delivered live rather than
		// stranded in the queue; draining afterwards then picks up the backlog.
		//
		// The acknowledgement is written before the backlog so that a client can
		// treat "ok" as "my mailbox is live from now on" and then read held
		// envelopes without demultiplexing them from the reply. Ordering between a
		// just-arrived live message and the backlog can therefore interleave, which
		// is harmless: SCS-1 frames carry their own counters and the receiving
		// ratchet reorders them anyway.
		var backlog [][]byte
		if g.queue != nil {
			for _, t := range tokens {
				backlog = append(backlog, g.queue.Drain(queue.Token(t))...)
			}
		}

		if err := conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyOK})); err != nil {
			return err
		}

		for _, envelope := range backlog {
			if err := conn.WriteBinary(envelope); err != nil {
				return err
			}
			g.metrics.EnvelopeDelivered()
		}
		return nil

	case TypeUnsubscribe:
		tokens, err := parseTokens(msg.Tokens)
		if err != nil {
			return g.replyError(conn, err.Error())
		}
		for _, t := range tokens {
			g.router.Unsubscribe(t, id)
		}
		g.metrics.SetMailboxes(g.mailboxCount())
		return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyOK}))

	case TypeHeartbeat:
		return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyHeartbeat}))

	default:
		return g.replyError(conn, fmt.Sprintf("unknown control type %q", msg.Type))
	}
}

// handleEnvelope routes one envelope.
func (g *Gateway) handleEnvelope(conn *ws.Conn, payload []byte) error {
	g.metrics.EnvelopeReceived(len(payload))

	if len(payload) < TokenSize {
		g.metrics.EnvelopeRejected()
		return g.replyError(conn, "envelope is shorter than a delivery token")
	}
	if g.cfg.Limits.MaxEnvelopeSize > 0 && int64(len(payload)) > g.cfg.Limits.MaxEnvelopeSize {
		g.metrics.EnvelopeRejected()
		return g.replyError(conn, "envelope exceeds the configured size limit")
	}

	var token router.Token
	copy(token[:], payload[:TokenSize])

	// The payload is forwarded byte for byte, token included, so the recipient
	// sees exactly what was deposited. The relay never needs to understand it.
	targets := g.router.Online(token)

	if len(targets) == 0 {
		if g.queue == nil {
			// Live mode: refuse rather than pretend. A sender that is told
			// "offline" can retry or switch channel; a sender that is told
			// nothing assumes delivery and stops trying.
			g.metrics.EnvelopeDropped()
			return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyOffline}))
		}

		if err := g.queue.Enqueue(queue.Token(token), payload); err != nil {
			g.metrics.EnvelopeRejected()
			return g.replyError(conn, "the relay is at capacity")
		}
		return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyQueued}))
	}

	delivered := 0
	for _, target := range targets {
		targetConn := g.connFor(target)
		if targetConn == nil {
			continue
		}
		if err := targetConn.WriteBinary(payload); err != nil {
			// A failing recipient must not take down the sender's connection;
			// the router entry will be cleaned up when that peer's own goroutine
			// unwinds.
			g.log.Debug("delivery to a live connection failed", "target", target, "err", err)
			continue
		}
		delivered++
	}

	if delivered == 0 {
		g.metrics.EnvelopeDropped()
		return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyOffline}))
	}

	for i := 0; i < delivered; i++ {
		g.metrics.EnvelopeDelivered()
	}
	return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyDelivered, Count: delivered}))
}

func (g *Gateway) replyError(conn *ws.Conn, message string) error {
	return conn.WriteText(marshalServerMessage(serverMessage{Type: ReplyError, Message: message}))
}

func (g *Gateway) registerConn(id router.ConnID, conn *ws.Conn) {
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	g.conns[id] = conn
}

func (g *Gateway) unregisterConn(id router.ConnID) {
	// Remove from the router first so that a concurrent delivery cannot pick up a
	// connection that is about to disappear from the map.
	g.router.RemoveConn(id)

	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	delete(g.conns, id)
}

func (g *Gateway) connFor(id router.ConnID) *ws.Conn {
	g.connsMu.RLock()
	defer g.connsMu.RUnlock()
	return g.conns[id]
}

func (g *Gateway) mailboxCount() int {
	mailboxes, _ := g.router.Stats()
	return mailboxes
}

// ConnCount reports how many client connections are currently live. It exists for
// tests and for the metrics endpoint.
func (g *Gateway) ConnCount() int {
	g.connsMu.RLock()
	defer g.connsMu.RUnlock()
	return len(g.conns)
}

func marshalServerMessage(msg serverMessage) []byte {
	// json.Marshal cannot fail for this struct: every field is a string or an int.
	raw, _ := json.Marshal(msg)
	return raw
}

// parseTokens decodes the hex token strings a client subscribes to.
func parseTokens(raw []string) ([]router.Token, error) {
	if len(raw) == 0 {
		return nil, errors.New("no tokens supplied")
	}
	// Bound the subscription set: without a limit one client can grow the router
	// without bound, which is a denial-of-service lever.
	const maxTokens = 256
	if len(raw) > maxTokens {
		return nil, fmt.Errorf("too many tokens (limit %d)", maxTokens)
	}

	tokens := make([]router.Token, 0, len(raw))
	for _, s := range raw {
		decoded, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("token is not valid hex")
		}
		if len(decoded) != TokenSize {
			return nil, fmt.Errorf("token must be %d bytes", TokenSize)
		}
		var t router.Token
		copy(t[:], decoded)
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// rateLimiter is a fixed-window counter.
//
// A fixed window is chosen over a token bucket because the failure mode is
// harmless here: a client that sends exactly at a window boundary may briefly
// exceed the limit by a factor of two, and this limiter exists to stop a flood,
// not to police a quota.
type rateLimiter struct {
	limit int

	mu    sync.Mutex
	start time.Time
	used  int
}

func newRateLimiter(limit int) *rateLimiter {
	if limit <= 0 {
		limit = 1 << 30 // effectively unlimited
	}
	return &rateLimiter{limit: limit}
}

func (r *rateLimiter) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now.Sub(r.start) >= time.Second {
		r.start = now
		r.used = 0
	}
	r.used++
	return r.used <= r.limit
}
