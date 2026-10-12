package ws

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// A deliberately independent client implementation.
//
// It is written from RFC 6455 rather than reusing the package's own code, so that
// a shared misreading of the specification cannot make both sides agree on
// something wrong. The masking path in particular is client-only in the real
// world and appears nowhere in the server implementation.
// --------------------------------------------------------------------------

type testClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	key  string
}

func dialWS(t *testing.T, rawURL string) *testClient {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parsing %q: %v", rawURL, err)
	}

	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dialling %s: %v", u.Host, err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating handshake nonce: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(nonce)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", u.Path, u.Host, key)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("writing handshake: %v", err)
	}

	c := &testClient{t: t, conn: conn, br: bufio.NewReader(conn), key: key}

	status, err := c.br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading handshake status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("expected 101 Switching Protocols, got %q", strings.TrimSpace(status))
	}

	headers := map[string]string{}
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading handshake headers: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}

	if got, want := headers["sec-websocket-accept"], acceptKey(key); got != want {
		t.Fatalf("Sec-WebSocket-Accept is %q, want %q", got, want)
	}
	if !strings.EqualFold(headers["upgrade"], "websocket") {
		t.Fatalf("missing Upgrade header: %v", headers)
	}

	t.Cleanup(func() { conn.Close() })
	return c
}

// writeFrame writes a client frame with the mask bit set, as RFC 6455 requires of
// clients.
func (c *testClient) writeFrame(fin bool, opcode byte, payload []byte, masked bool) error {
	c.t.Helper()

	var header []byte
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	header = append(header, b0)

	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}

	switch {
	case len(payload) <= 125:
		header = append(header, maskBit|byte(len(payload)))
	case len(payload) <= 0xFFFF:
		header = append(header, maskBit|126)
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	default:
		header = append(header, maskBit|127)
		header = binary.BigEndian.AppendUint64(header, uint64(len(payload)))
	}

	out := payload
	if masked {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		header = append(header, key[:]...)
		out = append([]byte(nil), payload...)
		applyMask(out, key)
	}

	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if len(out) > 0 {
		if _, err := c.conn.Write(out); err != nil {
			return err
		}
	}
	return nil
}

// readFrame reads one server frame. Server frames must not be masked, so the
// client asserts that too.
func (c *testClient) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	c.t.Helper()

	var header [2]byte
	if _, err := io.ReadFull(c.br, header[:]); err != nil {
		return false, 0, nil, err
	}
	fin = header[0]&0x80 != 0
	opcode = header[0] & 0x0F

	if header[1]&0x80 != 0 {
		return false, 0, nil, fmt.Errorf("server frame was masked, which RFC 6455 forbids")
	}

	length := int64(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}

	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return false, 0, nil, err
		}
	}
	return fin, opcode, payload, nil
}

// echoServer starts a WebSocket server that echoes every message back.
func echoServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()

	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 5 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 5 * time.Second
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r, opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer conn.CloseNow()

		for {
			op, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(op, payload); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wsURL(srv *httptest.Server) string {
	return "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/ws"
}

// --------------------------------------------------------------------------
// Handshake
// --------------------------------------------------------------------------

// TestAcceptKeyRFCExample checks the accept computation against the worked example
// in RFC 6455 section 1.3. This is the one place in the project where SHA-1 is
// correct, and the test pins why.
func TestAcceptKeyRFCExample(t *testing.T) {
	got := acceptKey("dGhlIHNhbXBsZSBub25jZQ==")
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Fatalf("acceptKey = %q, want %q", got, want)
	}
}

func TestHeaderContainsToken(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, Upgrade")

	if !headerContainsToken(h, "Connection", "upgrade") {
		t.Fatal("failed to find 'upgrade' inside a token list")
	}
	if headerContainsToken(h, "Connection", "close") {
		t.Fatal("matched a token that is not present")
	}
	// net/http canonicalises header names, so a lowercase lookup must still work.
	if !headerContainsToken(h, "connection", "Upgrade") {
		t.Fatal("token matching must be case-insensitive")
	}
}

func TestUpgradeRejectsNonWebSocketRequests(t *testing.T) {
	cases := []struct {
		name string
		req  *http.Request
	}{
		{
			name: "wrong method",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/ws", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				return r
			}(),
		},
		{
			name: "missing connection header",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/ws", nil)
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				return r
			}(),
		},
		{
			name: "missing upgrade header",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/ws", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				return r
			}(),
		},
		{
			name: "wrong version",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/ws", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "8")
				r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				return r
			}(),
		},
		{
			name: "malformed key",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/ws", nil)
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				r.Header.Set("Sec-WebSocket-Version", "13")
				r.Header.Set("Sec-WebSocket-Key", "not base64!!")
				return r
			}(),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if _, err := Upgrade(rec, c.req, Options{}); err == nil {
				t.Fatal("expected the upgrade to be rejected")
			}
		})
	}
}

func TestUpgradeRejectsOriginWhenConfigured(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "https://evil.example")

	rec := httptest.NewRecorder()
	opts := Options{CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "https://good.example"
	}}

	if _, err := Upgrade(rec, req, opts); err == nil {
		t.Fatal("a rejected origin must not complete the handshake")
	}
}

// --------------------------------------------------------------------------
// Framing
// --------------------------------------------------------------------------

// TestEchoAcrossLengthBoundaries exercises the three length encodings: 7-bit,
// 16-bit extended (126) and 64-bit extended (127).
func TestEchoAcrossLengthBoundaries(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 20})
	client := dialWS(t, wsURL(srv))

	// 125 is the last 7-bit length, 126 the first extended 16-bit one, 65535 the
	// last 16-bit one and 65536 the first 64-bit one.
	for _, size := range []int{0, 1, 125, 126, 127, 1000, 65535, 65536, 100000} {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}

			if err := client.writeFrame(true, OpBinary, payload, true); err != nil {
				t.Fatalf("writing frame: %v", err)
			}

			fin, op, got, err := client.readFrame()
			if err != nil {
				t.Fatalf("reading echo: %v", err)
			}
			if !fin || op != OpBinary {
				t.Fatalf("got fin=%v opcode=%#x", fin, op)
			}
			if len(got) != size {
				t.Fatalf("echoed %d bytes, want %d", len(got), size)
			}
			for i := range got {
				if got[i] != payload[i] {
					t.Fatalf("byte %d is %#x, want %#x", i, got[i], payload[i])
				}
			}
		})
	}
}

func TestEchoText(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	const msg = "SCHAT relay control channel"
	if err := client.writeFrame(true, OpText, []byte(msg), true); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	_, op, got, err := client.readFrame()
	if err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if op != OpText || string(got) != msg {
		t.Fatalf("got opcode %#x payload %q", op, got)
	}
}

// TestUnmaskedClientFrameIsRejected is a mandatory RFC 6455 rule
// (section 5.1): the server must fail the connection, not merely tolerate it.
func TestUnmaskedClientFrameIsRejected(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	if err := client.writeFrame(true, OpBinary, []byte("unmasked"), false); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	_, op, payload, err := client.readFrame()
	if err != nil {
		// Closing without a frame is also acceptable; what matters is that the
		// server did not echo the message back.
		return
	}
	if op == OpBinary {
		t.Fatalf("server echoed an unmasked client frame: %q", payload)
	}
	if op != OpClose {
		t.Fatalf("expected a close frame, got opcode %#x", op)
	}
}

func TestReservedBitsAreRejected(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	// FIN | RSV1 | binary, with a masked empty payload.
	var frame []byte
	frame = append(frame, 0x80|0x40|OpBinary, 0x80|0x00)
	frame = append(frame, 0x01, 0x02, 0x03, 0x04)
	if _, err := client.conn.Write(frame); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	if _, op, _, err := client.readFrame(); err == nil && op != OpClose {
		t.Fatalf("a frame with reserved bits set was accepted (opcode %#x)", op)
	}
}

func TestInvalidUTF8TextIsRejected(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	// 0xFF is never valid UTF-8.
	if err := client.writeFrame(true, OpText, []byte{0xFF, 0xFE}, true); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	if _, op, payload, err := client.readFrame(); err == nil && op == OpText {
		t.Fatalf("invalid UTF-8 text was echoed back: %q", payload)
	}
}

func TestOversizedMessageIsRejected(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1024})
	client := dialWS(t, wsURL(srv))

	if err := client.writeFrame(true, OpBinary, make([]byte, 4096), true); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	if _, op, _, err := client.readFrame(); err == nil && op == OpBinary {
		t.Fatal("a message larger than MaxMessageSize was accepted")
	}
}

// TestFragmentedMessageIsReassembled covers the continuation-frame path, which a
// relay will meet in practice because some clients fragment by default.
func TestFragmentedMessageIsReassembled(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	parts := [][]byte{[]byte("frag-"), []byte("ment-"), []byte("ed")}

	// First fragment: binary, FIN clear.
	if err := client.writeFrame(false, OpBinary, parts[0], true); err != nil {
		t.Fatalf("writing first fragment: %v", err)
	}
	// Middle fragment: continuation opcode, FIN clear.
	if err := client.writeFrame(false, OpContinuation, parts[1], true); err != nil {
		t.Fatalf("writing middle fragment: %v", err)
	}
	// Final fragment: continuation opcode, FIN set.
	if err := client.writeFrame(true, OpContinuation, parts[2], true); err != nil {
		t.Fatalf("writing final fragment: %v", err)
	}

	_, op, got, err := client.readFrame()
	if err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if op != OpBinary {
		t.Fatalf("got opcode %#x, want binary", op)
	}
	if string(got) != "frag-ment-ed" {
		t.Fatalf("reassembled to %q, want %q", got, "frag-ment-ed")
	}
}

func TestContinuationWithoutStartIsRejected(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	if err := client.writeFrame(true, OpContinuation, []byte("orphan"), true); err != nil {
		t.Fatalf("writing frame: %v", err)
	}

	if _, op, _, err := client.readFrame(); err == nil && op == OpBinary {
		t.Fatal("an orphan continuation frame was accepted")
	}
}

// TestPingIsAnsweredWithPong covers the keepalive path the relay depends on.
func TestPingIsAnsweredWithPong(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	if err := client.writeFrame(true, OpPing, []byte("hb"), true); err != nil {
		t.Fatalf("writing ping: %v", err)
	}

	_, op, payload, err := client.readFrame()
	if err != nil {
		t.Fatalf("reading pong: %v", err)
	}
	if op != OpPong {
		t.Fatalf("got opcode %#x, want pong", op)
	}
	if string(payload) != "hb" {
		t.Fatalf("pong payload is %q, want %q", payload, "hb")
	}

	// The connection must still be usable after the control exchange.
	if err := client.writeFrame(true, OpBinary, []byte("after ping"), true); err != nil {
		t.Fatalf("writing frame: %v", err)
	}
	if _, _, got, err := client.readFrame(); err != nil || string(got) != "after ping" {
		t.Fatalf("connection unusable after ping: got %q err %v", got, err)
	}
}

// TestCloseHandshake checks that the server completes the closing handshake
// instead of simply dropping the connection.
func TestCloseHandshake(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	var payload []byte
	payload = binary.BigEndian.AppendUint16(payload, CloseNormal)
	payload = append(payload, "done"...)

	if err := client.writeFrame(true, OpClose, payload, true); err != nil {
		t.Fatalf("writing close: %v", err)
	}

	_, op, _, err := client.readFrame()
	if err != nil {
		t.Fatalf("expected a close frame in reply, got error %v", err)
	}
	if op != OpClose {
		t.Fatalf("got opcode %#x, want close", op)
	}
}

func TestOversizedControlFrameIsRejected(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16})
	client := dialWS(t, wsURL(srv))

	// Control frames may not exceed 125 bytes.
	if err := client.writeFrame(true, OpPing, make([]byte, 200), true); err != nil {
		t.Fatalf("writing oversize ping: %v", err)
	}

	if _, op, _, err := client.readFrame(); err == nil && op == OpPong {
		t.Fatal("an oversized control frame was accepted")
	}
}

// TestNegotiatesSubprotocol covers the negotiated-header path even though the
// relay does not currently use it.
func TestNegotiatesSubprotocol(t *testing.T) {
	srv := echoServer(t, Options{MaxMessageSize: 1 << 16, Subprotocols: []string{"schat.v1"}})

	u, _ := url.Parse(wsURL(srv))
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Protocol: schat.v1\r\n\r\n", u.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("writing handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	seen := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading handshake: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.EqualFold(line, "Sec-WebSocket-Protocol: schat.v1") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("the server did not echo the negotiated subprotocol")
	}
}
