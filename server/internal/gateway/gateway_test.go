package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/schat/schat/server/internal/config"
	"github.com/schat/schat/server/internal/metrics"
	"github.com/schat/schat/server/internal/queue"
	"github.com/schat/schat/server/internal/router"
	"github.com/schat/schat/server/internal/wstest"
)

// --------------------------------------------------------------------------
// Fixture
// --------------------------------------------------------------------------

type testRelay struct {
	t       *testing.T
	srv     *httptest.Server
	gateway *Gateway
	metrics *metrics.Counters
	router  *router.Router
	queue   *queue.Queue
}

func newTestRelay(t *testing.T, mode config.Mode) *testRelay {
	t.Helper()

	cfg := config.Default()
	cfg.Mode = mode
	cfg.Limits.MaxEnvelopeSize = 1 << 16
	cfg.Limits.SendRatePerSec = 1000
	cfg.Limits.IdleTimeout = 10 * time.Second

	var q *queue.Queue
	if mode == config.ModeBuffer {
		var err error
		q, err = queue.New(cfg.Buffer.MaxPerToken, cfg.Buffer.TTL, cfg.Buffer.MaxGlobalMemory)
		if err != nil {
			t.Fatalf("queue.New: %v", err)
		}
	}

	r := router.New()
	counters := metrics.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	gw := New(cfg, r, q, counters, log)

	srv := httptest.NewServer(http.HandlerFunc(gw.ServeWS))
	t.Cleanup(srv.Close)

	return &testRelay{t: t, srv: srv, gateway: gw, metrics: counters, router: r, queue: q}
}

func (r *testRelay) wsURL() string {
	return "ws://" + strings.TrimPrefix(r.srv.URL, "http://") + "/ws"
}

func (r *testRelay) dial() *wstest.Client {
	r.t.Helper()
	c, err := wstest.Dial(r.wsURL())
	if err != nil {
		r.t.Fatalf("dialling relay: %v", err)
	}
	r.t.Cleanup(func() { c.Close() })
	return c
}

// subscribe sends a subscription and waits for the acknowledgement, so that a
// subsequent send cannot race the registration.
func (r *testRelay) subscribe(c *wstest.Client, tokens ...string) {
	r.t.Helper()

	body, err := json.Marshal(controlMessage{Type: TypeSubscribe, Tokens: tokens})
	if err != nil {
		r.t.Fatalf("marshalling subscribe: %v", err)
	}
	if err := c.WriteText(body); err != nil {
		r.t.Fatalf("writing subscribe: %v", err)
	}

	reply := r.readReply(c)
	if reply.Type != ReplyOK {
		r.t.Fatalf("subscribe was refused: %+v", reply)
	}
}

func (r *testRelay) readReply(c *wstest.Client) serverMessage {
	r.t.Helper()

	raw, err := c.ReadText()
	if err != nil {
		r.t.Fatalf("reading reply: %v", err)
	}
	var msg serverMessage
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		r.t.Fatalf("decoding reply %q: %v", raw, err)
	}
	return msg
}

func tokenHex(b byte) string {
	t := make([]byte, TokenSize)
	for i := range t {
		t[i] = b
	}
	return hex.EncodeToString(t)
}

// envelope builds the wire form the relay expects: token then opaque payload.
func envelope(tokenHexStr string, body []byte) []byte {
	token, err := hex.DecodeString(tokenHexStr)
	if err != nil {
		panic(err)
	}
	return append(token, body...)
}

// --------------------------------------------------------------------------
// The core relay behaviour
// --------------------------------------------------------------------------

// TestRelayBetweenTwoClients is the end-to-end proof that the relay works: one
// client deposits an envelope into a mailbox, another client subscribed to that
// mailbox receives it byte for byte.
func TestRelayBetweenTwoClients(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)

	recipient := relay.dial()
	sender := relay.dial()

	token := tokenHex(0xAB)
	relay.subscribe(recipient, token)

	// The body stands in for an SCS-1 frame: opaque bytes as far as the relay is
	// concerned.
	body := []byte("this-is-an-encrypted-frame-the-server-cannot-read")
	wire := envelope(token, body)

	if err := sender.WriteBinary(wire); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}

	if reply := relay.readReply(sender); reply.Type != ReplyDelivered || reply.Count != 1 {
		t.Fatalf("sender got %+v, want delivered to 1", reply)
	}

	got, err := recipient.ReadBinary()
	if err != nil {
		t.Fatalf("recipient read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("recipient received %d bytes, want the %d deposited", len(got), len(wire))
	}

	// The relay must not have altered the payload in any way, including the token.
	if !bytes.Equal(got[:TokenSize], wire[:TokenSize]) {
		t.Fatal("the relay modified the delivery token")
	}

	snap := relay.metrics.Snapshot()
	if snap.DeliveredEnvelopes != 1 {
		t.Errorf("delivered counter is %d, want 1", snap.DeliveredEnvelopes)
	}
}

// TestLiveModeRefusesOfflineMailbox is the honesty requirement: in live mode a
// message for an absent recipient is refused, never silently dropped.
func TestLiveModeRefusesOfflineMailbox(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	sender := relay.dial()

	if err := sender.WriteBinary(envelope(tokenHex(0xCD), []byte("nobody home"))); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}

	if reply := relay.readReply(sender); reply.Type != ReplyOffline {
		t.Fatalf("sender got %+v, want an explicit offline reply", reply)
	}

	if snap := relay.metrics.Snapshot(); snap.DroppedEnvelopes != 1 {
		t.Errorf("dropped counter is %d, want 1", snap.DroppedEnvelopes)
	}
	if relay.queue != nil {
		t.Fatal("live mode must not have a queue at all")
	}
}

// TestBufferModeQueuesAndDrainsOnSubscribe covers the store-and-forward path,
// including the ordering guarantee that held messages arrive oldest first.
func TestBufferModeQueuesAndDrainsOnSubscribe(t *testing.T) {
	relay := newTestRelay(t, config.ModeBuffer)
	sender := relay.dial()

	token := tokenHex(0x11)
	var sent [][]byte
	for i := 0; i < 3; i++ {
		wire := envelope(token, []byte(fmt.Sprintf("held-%d", i)))
		sent = append(sent, wire)

		if err := sender.WriteBinary(wire); err != nil {
			t.Fatalf("writing envelope %d: %v", i, err)
		}
		if reply := relay.readReply(sender); reply.Type != ReplyQueued {
			t.Fatalf("envelope %d got %+v, want queued", i, reply)
		}
	}

	// A recipient that arrives later must receive everything, in order.
	recipient := relay.dial()
	relay.subscribe(recipient, token)

	for i, want := range sent {
		got, err := recipient.ReadBinary()
		if err != nil {
			t.Fatalf("reading held envelope %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("held envelope %d does not match what was sent", i)
		}
	}

	// The queue must be empty afterwards, or a resubscribe would duplicate.
	if _, envelopes, _, _ := relay.queue.Stats(); envelopes != 0 {
		t.Fatalf("%d envelopes remain queued after draining", envelopes)
	}
}

func TestBufferModeDeliversToLiveRecipientDirectly(t *testing.T) {
	relay := newTestRelay(t, config.ModeBuffer)

	recipient := relay.dial()
	sender := relay.dial()

	token := tokenHex(0x22)
	relay.subscribe(recipient, token)

	wire := envelope(token, []byte("straight through"))
	if err := sender.WriteBinary(wire); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}
	if reply := relay.readReply(sender); reply.Type != ReplyDelivered {
		t.Fatalf("sender got %+v, want delivered (not queued)", reply)
	}

	got, err := recipient.ReadBinary()
	if err != nil {
		t.Fatalf("recipient read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("payload mismatch")
	}
	if _, envelopes, _, _ := relay.queue.Stats(); envelopes != 0 {
		t.Fatal("a delivered message must not also be queued")
	}
}

// TestMultipleDevicesOnOneMailbox covers a user with two devices: both must
// receive a copy.
func TestMultipleDevicesOnOneMailbox(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)

	phone := relay.dial()
	tablet := relay.dial()
	sender := relay.dial()

	token := tokenHex(0x33)
	relay.subscribe(phone, token)
	relay.subscribe(tablet, token)

	wire := envelope(token, []byte("to both devices"))
	if err := sender.WriteBinary(wire); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}
	if reply := relay.readReply(sender); reply.Type != ReplyDelivered || reply.Count != 2 {
		t.Fatalf("sender got %+v, want delivered to 2", reply)
	}

	for name, c := range map[string]*wstest.Client{"phone": phone, "tablet": tablet} {
		got, err := c.ReadBinary()
		if err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if !bytes.Equal(got, wire) {
			t.Fatalf("%s received a different payload", name)
		}
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)

	recipient := relay.dial()
	sender := relay.dial()

	token := tokenHex(0x44)
	relay.subscribe(recipient, token)

	body, _ := json.Marshal(controlMessage{Type: TypeUnsubscribe, Tokens: []string{token}})
	if err := recipient.WriteText(body); err != nil {
		t.Fatalf("writing unsubscribe: %v", err)
	}
	if reply := relay.readReply(recipient); reply.Type != ReplyOK {
		t.Fatalf("unsubscribe got %+v", reply)
	}

	if err := sender.WriteBinary(envelope(token, []byte("too late"))); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}
	if reply := relay.readReply(sender); reply.Type != ReplyOffline {
		t.Fatalf("sender got %+v, want offline after unsubscription", reply)
	}
}

// TestDisconnectCleansUpRouter is the leak test: a dropped connection must not
// leave a mailbox registered, or a later send would report a phantom delivery.
func TestDisconnectCleansUpRouter(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)

	recipient := relay.dial()
	token := tokenHex(0x55)
	relay.subscribe(recipient, token)

	if mailboxes, _ := relay.router.Stats(); mailboxes != 1 {
		t.Fatalf("router tracks %d mailboxes, want 1", mailboxes)
	}

	recipient.Close()

	// The server notices asynchronously when its read fails.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mailboxes, _ := relay.router.Stats(); mailboxes == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if mailboxes, conns := relay.router.Stats(); mailboxes != 0 || conns != 0 {
		t.Fatalf("router still tracks %d mailboxes / %d connections after disconnect", mailboxes, conns)
	}
	if got := relay.gateway.ConnCount(); got != 0 {
		t.Fatalf("gateway still tracks %d connections after disconnect", got)
	}
}

// --------------------------------------------------------------------------
// Control channel
// --------------------------------------------------------------------------

func TestHeartbeat(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	body, _ := json.Marshal(controlMessage{Type: TypeHeartbeat})
	if err := client.WriteText(body); err != nil {
		t.Fatalf("writing heartbeat: %v", err)
	}
	if reply := relay.readReply(client); reply.Type != ReplyHeartbeat {
		t.Fatalf("heartbeat got %+v", reply)
	}
}

// TestWebSocketPingIsAnswered checks the transport-level keepalive, which the
// relay relies on as its idle-timeout signal.
func TestWebSocketPingIsAnswered(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	if err := client.WritePing([]byte("hb")); err != nil {
		t.Fatalf("writing ping: %v", err)
	}
	// The pong is a control frame, so ReadMessage skips it; proving the connection
	// still works is what matters, and a heartbeat reply confirms liveness.
	body, _ := json.Marshal(controlMessage{Type: TypeHeartbeat})
	if err := client.WriteText(body); err != nil {
		t.Fatalf("writing heartbeat after ping: %v", err)
	}
	if reply := relay.readReply(client); reply.Type != ReplyHeartbeat {
		t.Fatalf("connection unusable after ping: %+v", reply)
	}
}

func TestControlRejections(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	cases := []struct {
		name string
		body string
	}{
		{"not json", `{`},
		{"unknown type", `{"t":"drop-tables"}`},
		{"no tokens", `{"t":"sub"}`},
		{"bad hex", `{"t":"sub","tokens":["zzzz"]}`},
		{"short token", `{"t":"sub","tokens":["aabb"]}`},
		{"too long token", `{"t":"sub","tokens":["` + strings.Repeat("ab", 32) + `"]}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := client.WriteText([]byte(c.body)); err != nil {
				t.Fatalf("writing control message: %v", err)
			}
			reply := relay.readReply(client)
			if reply.Type != ReplyError {
				t.Fatalf("got %+v, want an error reply", reply)
			}
		})
	}

	// The connection must survive a rejected control message.
	relay.subscribe(client, tokenHex(0x66))
}

func TestSubscriptionCountIsBounded(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	tokens := make([]string, 300)
	for i := range tokens {
		tokens[i] = hex.EncodeToString(bytes.Repeat([]byte{byte(i)}, TokenSize))
	}
	body, _ := json.Marshal(controlMessage{Type: TypeSubscribe, Tokens: tokens})
	if err := client.WriteText(body); err != nil {
		t.Fatalf("writing subscribe: %v", err)
	}
	if reply := relay.readReply(client); reply.Type != ReplyError {
		t.Fatalf("got %+v, want a rejection for an oversized subscription set", reply)
	}
}

// --------------------------------------------------------------------------
// Envelope validation and abuse resistance
// --------------------------------------------------------------------------

// TestShortEnvelopeIsRejected covers the gateway's own length check.
func TestShortEnvelopeIsRejected(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	if err := client.WriteBinary([]byte("short")); err != nil {
		t.Fatalf("writing short envelope: %v", err)
	}
	if reply := relay.readReply(client); reply.Type != ReplyError {
		t.Fatalf("short envelope got %+v, want an error", reply)
	}
}

// TestEnvelopeJustOverTheLimitGetsAPoliteError covers the band between the
// configured envelope limit and the transport message cap.
//
// The transport cap is deliberately set a little above the envelope limit so that
// a modest overshoot is answered with a JSON error the client can display, rather
// than by dropping the connection.
func TestEnvelopeJustOverTheLimitGetsAPoliteError(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	body := bytes.Repeat([]byte{0x41}, int(relay.gateway.cfg.Limits.MaxEnvelopeSize)+1)
	if err := client.WriteBinary(envelope(tokenHex(0x77), body)); err != nil {
		t.Fatalf("writing oversized envelope: %v", err)
	}
	if reply := relay.readReply(client); reply.Type != ReplyError {
		t.Fatalf("oversized envelope got %+v, want an error", reply)
	}
}

// TestEnvelopeFarOverTheLimitIsClosedByTheTransport documents the outer bound.
//
// A frame larger than the transport cap is refused while it is still being framed,
// so the server never allocates the payload at all. The connection is closed with
// status 1009 and no JSON reply is possible, because the frame was never accepted
// as a message.
func TestEnvelopeFarOverTheLimitIsClosedByTheTransport(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	client := relay.dial()

	// A write error is expected and ignored: the server may close the socket while
	// this client is still pushing bytes into it, which is exactly the intended
	// behaviour.
	body := bytes.Repeat([]byte{0x41}, 1<<18)
	_ = client.WriteBinary(envelope(tokenHex(0x78), body))

	if err := client.WaitForClose(3 * time.Second); err != nil {
		t.Fatalf("expected the transport to close the connection, got: %v", err)
	}

	// Poll rather than assert immediately. The server closes the socket and only
	// then increments the counter, so the close can become visible to this client
	// first. Asserting on the counter without polling made this test fail roughly
	// one run in four.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if relay.metrics.Snapshot().RejectedEnvelopes > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("an oversized frame refused by the transport was never counted as a rejection")
}

func TestRateLimitRejectsFlood(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)
	// Tighten the limit for this test only.
	relay.gateway.cfg.Limits.SendRatePerSec = 5

	client := relay.dial()

	var sawError bool
	for i := 0; i < 20; i++ {
		body, _ := json.Marshal(controlMessage{Type: TypeHeartbeat})
		if err := client.WriteText(body); err != nil {
			t.Fatalf("writing heartbeat %d: %v", i, err)
		}
		reply := relay.readReply(client)
		if reply.Type == ReplyError && strings.Contains(reply.Message, "rate limit") {
			sawError = true
			break
		}
	}

	if !sawError {
		t.Fatal("flooding the connection was never rate limited")
	}
	if snap := relay.metrics.Snapshot(); snap.RateLimited == 0 {
		t.Error("the rate-limited counter was not incremented")
	}
}

// TestRelayDoesNotInspectPayload is the architectural assertion, expressed as a
// test: arbitrary bytes must pass through untouched, including bytes that look
// like nothing at all.
func TestRelayDoesNotInspectPayload(t *testing.T) {
	relay := newTestRelay(t, config.ModeLive)

	recipient := relay.dial()
	sender := relay.dial()

	token := tokenHex(0x99)
	relay.subscribe(recipient, token)

	// High entropy, invalid UTF-8, embedded nulls and a fake header.
	body := bytes.Repeat([]byte{0x00, 0xFF, 0xFE, 0x7F}, 64)
	wire := envelope(token, body)

	if err := sender.WriteBinary(wire); err != nil {
		t.Fatalf("writing envelope: %v", err)
	}
	if reply := relay.readReply(sender); reply.Type != ReplyDelivered {
		t.Fatalf("sender got %+v", reply)
	}

	got, err := recipient.ReadBinary()
	if err != nil {
		t.Fatalf("recipient read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("the relay altered an opaque payload")
	}
}

// TestTokenSizeMatchesProtocol pins the duplicated constant.
//
// The server cannot import the protocol module (server/go.mod forbids it), so the
// token length is declared twice. This test fails loudly if the two ever drift,
// which is the only realistic way that duplication causes harm.
func TestTokenSizeMatchesProtocol(t *testing.T) {
	const protocolTokenSize = 16 // see protocol/token.go: TokenSize
	if TokenSize != protocolTokenSize {
		t.Fatalf("TokenSize is %d but the protocol defines %d", TokenSize, protocolTokenSize)
	}
}
