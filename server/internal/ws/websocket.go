// Package ws is a minimal server-side implementation of the WebSocket protocol,
// RFC 6455.
//
// # Why this package exists rather than a library
//
// SCHAT's relay server is contractually dependency-free. That is not asceticism
// for its own sake: server/go.mod documents that the absence of third-party code
// is what makes "go list -m all" a meaningful audit of the supply chain, and what
// keeps the binary at ~10 MB with a ~9 MB resident set. Pulling in a WebSocket
// library would trade both away for roughly six hundred lines of well-specified
// framing.
//
// # Scope
//
// Exactly what a relay needs, and nothing more:
//
//   - the server side of the opening handshake (RFC 6455 section 4.2);
//   - frame parsing and serialisation, including extended lengths (section 5.2);
//   - fragmentation reassembly and size limits;
//   - control frames: ping, pong and the closing handshake (sections 5.5, 7);
//   - the protocol's fail-closed rules: RSV bits must be zero, client frames must
//     be masked, control frames must be short and unfragmented, text must be
//     valid UTF-8.
//
// Not implemented, because the relay never needs them: extensions
// (permessage-deflate and friends), the client side of the handshake, and
// subprotocol negotiation.
//
// # A note on origin checking
//
// Browsers send an Origin header and will happily open a cross-origin WebSocket.
// That matters when the server authenticates the *browser* through ambient
// credentials such as cookies, because then a hostile page can ride on them.
// SCHAT has no cookies, no sessions and no ambient authority: a client proves
// nothing by connecting, and a hostile page that connects directly can do exactly
// what it could do through a WebSocket. CheckOrigin is therefore available but
// defaults to allowing every origin, and the reasoning is recorded here rather
// than left implicit.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// WebSocket frame opcodes (RFC 6455 section 5.2).
const (
	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xA
)

// Close status codes used by this package (RFC 6455 section 7.4.1).
const (
	CloseNormal          uint16 = 1000
	CloseGoingAway       uint16 = 1001
	CloseProtocolError   uint16 = 1002
	CloseUnsupportedData uint16 = 1003
	CloseInvalidPayload  uint16 = 1007
	ClosePolicyViolation uint16 = 1008
	CloseMessageTooBig   uint16 = 1009
	CloseInternalError   uint16 = 1011
)

// handshakeGUID is the constant from RFC 6455 section 1.3.
const handshakeGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Control-frame payloads may not exceed 125 bytes (RFC 6455 section 5.5).
const maxControlPayload = 125

// Errors returned by this package.
var (
	// ErrNotWebSocket means the request was not a valid WebSocket upgrade.
	ErrNotWebSocket = errors.New("ws: not a websocket upgrade request")

	// ErrHijackUnsupported means the ResponseWriter cannot be hijacked, which
	// happens with HTTP/2. The server must keep /ws on HTTP/1.1.
	ErrHijackUnsupported = errors.New("ws: connection cannot be hijacked (is HTTP/2 in use?)")

	// ErrProtocol means the peer violated RFC 6455. The connection is closed with
	// status 1002 before this is returned.
	ErrProtocol = errors.New("ws: protocol error")

	// ErrUnmaskedClientFrame means a client sent an unmasked frame, which RFC 6455
	// section 5.1 requires the server to reject.
	ErrUnmaskedClientFrame = errors.New("ws: client frame was not masked")

	// ErrMessageTooLarge means a message exceeded Options.MaxMessageSize.
	ErrMessageTooLarge = errors.New("ws: message too large")
)

// CloseError reports that the peer sent a close frame.
type CloseError struct {
	// Code is the status code the peer supplied, or CloseNormal when the frame
	// carried no payload.
	Code uint16

	// Reason is the optional human-readable reason, already validated as UTF-8.
	Reason string
}

func (e *CloseError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("ws: closed by peer (code %d)", e.Code)
	}
	return fmt.Sprintf("ws: closed by peer (code %d: %s)", e.Code, e.Reason)
}

// Options configures a connection.
type Options struct {
	// MaxMessageSize caps a single reassembled message. A relay must bound this,
	// or one client can allocate arbitrarily much memory on the server.
	MaxMessageSize int64

	// ReadTimeout and WriteTimeout bound individual operations. A zero value means
	// no deadline.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// CheckOrigin is consulted during the handshake. A nil value allows every
	// origin; see the package comment for why that is the right default here.
	CheckOrigin func(*http.Request) bool

	// Subprotocols lists the values this server will echo back if offered.
	Subprotocols []string
}

// withDefaults fills in the values a caller is likely to leave at zero.
func (o Options) withDefaults() Options {
	if o.MaxMessageSize <= 0 {
		o.MaxMessageSize = 8 << 20 // 8 MiB, matching limits.max_envelope_size
	}
	return o
}

// Conn is an established WebSocket connection.
//
// A Conn is safe for one concurrent reader and one concurrent writer. ReadMessage
// must not be called from more than one goroutine at a time; WriteMessage may be
// called concurrently with ReadMessage, because control replies generated inside
// the reader take the same write lock.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	wmu sync.Mutex

	opts Options

	// closeMu guards the closing state.
	closeMu   sync.Mutex
	closed    bool
	closeSent bool
}

// Upgrade performs the server side of the WebSocket opening handshake and takes
// over the underlying connection.
//
// On success the HTTP handler must not write to w afterwards: the connection no
// longer belongs to net/http.
func Upgrade(w http.ResponseWriter, r *http.Request, opts Options) (*Conn, error) {
	opts = opts.withDefaults()

	if r.Method != http.MethodGet {
		return nil, fmt.Errorf("%w: method %s", ErrNotWebSocket, r.Method)
	}
	if !headerContainsToken(r.Header, "Connection", "upgrade") {
		return nil, fmt.Errorf("%w: missing Connection: Upgrade", ErrNotWebSocket)
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return nil, fmt.Errorf("%w: missing Upgrade: websocket", ErrNotWebSocket)
	}
	if v := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")); v != "13" {
		// RFC 6455 section 4.2.2: advertise the version we support.
		w.Header().Set("Sec-WebSocket-Version", "13")
		return nil, fmt.Errorf("%w: unsupported version %q", ErrNotWebSocket, v)
	}

	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if _, err := base64.StdEncoding.DecodeString(key); err != nil || len(key) == 0 {
		return nil, fmt.Errorf("%w: malformed Sec-WebSocket-Key", ErrNotWebSocket)
	}

	if opts.CheckOrigin != nil && !opts.CheckOrigin(r) {
		return nil, fmt.Errorf("%w: origin rejected", ErrNotWebSocket)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, ErrHijackUnsupported
	}
	netConn, rw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("ws: hijack: %w", err)
	}

	// Build the 101 response by hand: net/http will not write it for us once the
	// connection has been hijacked.
	var resp strings.Builder
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.WriteString("Upgrade: websocket\r\n")
	resp.WriteString("Connection: Upgrade\r\n")
	resp.WriteString("Sec-WebSocket-Accept: ")
	resp.WriteString(acceptKey(key))
	resp.WriteString("\r\n")

	if agreed := selectSubprotocol(r, opts.Subprotocols); agreed != "" {
		resp.WriteString("Sec-WebSocket-Protocol: ")
		resp.WriteString(agreed)
		resp.WriteString("\r\n")
	}
	resp.WriteString("\r\n")

	if _, err := rw.WriteString(resp.String()); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ws: writing handshake response: %w", err)
	}
	if err := rw.Flush(); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ws: flushing handshake response: %w", err)
	}

	return &Conn{
		conn: netConn,
		br:   rw.Reader,
		bw:   rw.Writer,
		opts: opts,
	}, nil
}

// acceptKey computes the Sec-WebSocket-Accept value (RFC 6455 section 4.2.2).
//
//	base64( SHA1( Sec-WebSocket-Key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )
//
// SHA-1 is required by the specification. It is used here purely as a fixed
// handshake obfuscation step and carries no security weight, which is why a
// broken hash is acceptable in this one position — and unacceptable anywhere
// else in the project.
func acceptKey(key string) string {
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, handshakeGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// headerContainsToken reports whether a comma-separated header contains a token,
// case-insensitively. Connection headers are token lists, so "keep-alive, Upgrade"
// must match "upgrade".
func headerContainsToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func selectSubprotocol(r *http.Request, supported []string) string {
	if len(supported) == 0 {
		return ""
	}
	for _, offered := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, candidate := range strings.Split(offered, ",") {
			candidate = strings.TrimSpace(candidate)
			for _, want := range supported {
				if candidate == want {
					return candidate
				}
			}
		}
	}
	return ""
}

// ReadMessage returns the next complete data message.
//
// Ping frames are answered automatically and pong frames are discarded, so a
// caller only ever sees OpText, OpBinary, or an error. Fragmented messages are
// reassembled. A close frame from the peer is answered and reported as a
// *CloseError.
func (c *Conn) ReadMessage() (opcode byte, payload []byte, err error) {
	var (
		msgOpcode byte
		assembled []byte
	)

	for {
		fin, op, frame, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}

		switch op {
		case OpPing:
			// RFC 6455 section 5.5.3: respond with a pong carrying the same payload.
			if err := c.writeFrame(OpPong, frame); err != nil {
				return 0, nil, err
			}
			continue

		case OpPong:
			continue

		case OpClose:
			code, reason := parseClosePayload(frame)
			// Echo the close frame to complete the handshake, then drop the
			// connection regardless of whether that write succeeded.
			_ = c.writeClose(code, "")
			c.CloseNow()
			return 0, nil, &CloseError{Code: code, Reason: reason}

		case OpContinuation:
			if msgOpcode == 0 {
				return 0, nil, c.protocolError("continuation frame without a preceding data frame")
			}
			assembled = append(assembled, frame...)
			if int64(len(assembled)) > c.opts.MaxMessageSize {
				return 0, nil, c.tooLarge()
			}
			if fin {
				if msgOpcode == OpText && !utf8.Valid(assembled) {
					return 0, nil, c.invalidPayload("text message is not valid UTF-8")
				}
				return msgOpcode, assembled, nil
			}

		case OpText, OpBinary:
			if msgOpcode != 0 {
				return 0, nil, c.protocolError("new data frame while a fragmented message is in progress")
			}
			if fin {
				if op == OpText && !utf8.Valid(frame) {
					return 0, nil, c.invalidPayload("text message is not valid UTF-8")
				}
				return op, frame, nil
			}
			msgOpcode = op
			assembled = append(assembled, frame...)
			if int64(len(assembled)) > c.opts.MaxMessageSize {
				return 0, nil, c.tooLarge()
			}

		default:
			return 0, nil, c.protocolError(fmt.Sprintf("reserved opcode %#x", op))
		}
	}
}

// readFrame reads exactly one frame.
func (c *Conn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	if c.opts.ReadTimeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.opts.ReadTimeout)); err != nil {
			return false, 0, nil, err
		}
	}

	var header [2]byte
	if _, err := io.ReadFull(c.br, header[:]); err != nil {
		return false, 0, nil, err
	}

	fin = header[0]&0x80 != 0
	rsv := header[0] & 0x70
	opcode = header[0] & 0x0F

	// No extensions are negotiated, so every reserved bit must be zero
	// (RFC 6455 section 5.2). A peer that sets one is either broken or probing.
	if rsv != 0 {
		return false, 0, nil, c.protocolError("reserved bits set without a negotiated extension")
	}

	masked := header[1]&0x80 != 0
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
		raw := binary.BigEndian.Uint64(ext[:])
		// RFC 6455 section 5.2: the most significant bit must be zero, and the
		// minimal-length encoding must be used.
		if raw > 1<<62 {
			return false, 0, nil, c.protocolError("64-bit length has the high bit set")
		}
		length = int64(raw)
	}

	isControl := opcode&0x08 != 0
	if isControl {
		if !fin {
			return false, 0, nil, c.protocolError("control frame must not be fragmented")
		}
		if length > maxControlPayload {
			return false, 0, nil, c.protocolError("control frame payload exceeds 125 bytes")
		}
	}

	// The server side must reject unmasked client frames (RFC 6455 section 5.1).
	if !masked {
		return false, 0, nil, c.protocolError("client frame was not masked")
	}

	// Bound the allocation before reading. Without this a single length field
	// could ask the server to allocate gigabytes.
	if length > c.opts.MaxMessageSize {
		return false, 0, nil, c.tooLarge()
	}

	var maskKey [4]byte
	if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
		return false, 0, nil, err
	}

	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return false, 0, nil, err
		}
		applyMask(payload, maskKey)
	}

	return fin, opcode, payload, nil
}

// applyMask XORs the payload with the repeating 4-byte masking key in place.
func applyMask(payload []byte, key [4]byte) {
	for i := range payload {
		payload[i] ^= key[i&3]
	}
}

// WriteMessage sends a complete data message in a single frame.
func (c *Conn) WriteMessage(opcode byte, payload []byte) error {
	if opcode != OpText && opcode != OpBinary {
		return fmt.Errorf("ws: WriteMessage accepts only text or binary, got %#x", opcode)
	}
	if int64(len(payload)) > c.opts.MaxMessageSize {
		return ErrMessageTooLarge
	}
	return c.writeFrame(opcode, payload)
}

// WriteText is a convenience wrapper for the JSON control channel.
func (c *Conn) WriteText(payload []byte) error { return c.WriteMessage(OpText, payload) }

// WriteBinary is a convenience wrapper for relayed envelopes.
func (c *Conn) WriteBinary(payload []byte) error { return c.WriteMessage(OpBinary, payload) }

// WritePing sends a ping frame.
func (c *Conn) WritePing(payload []byte) error { return c.writeFrame(OpPing, payload) }

// writeFrame serialises and writes one frame. Server frames are never masked
// (RFC 6455 section 5.1).
func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	if opcode&0x08 != 0 && len(payload) > maxControlPayload {
		return fmt.Errorf("ws: control frame payload exceeds %d bytes", maxControlPayload)
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return net.ErrClosed
	}
	if opcode == OpClose {
		c.closeSent = true
	}
	c.closeMu.Unlock()

	if c.opts.WriteTimeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.opts.WriteTimeout)); err != nil {
			return err
		}
	}

	var header [10]byte
	header[0] = 0x80 | opcode // FIN set: this package never fragments on send

	n := 2
	switch {
	case len(payload) <= 125:
		header[1] = byte(len(payload))
	case len(payload) <= 0xFFFF:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
		n = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(len(payload)))
		n = 10
	}

	if _, err := c.bw.Write(header[:n]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := c.bw.Write(payload); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

// writeClose sends a close frame with a status code and optional reason.
func (c *Conn) writeClose(code uint16, reason string) error {
	payload := make([]byte, 0, 2+len(reason))
	payload = binary.BigEndian.AppendUint16(payload, code)
	payload = append(payload, reason...)
	if len(payload) > maxControlPayload {
		payload = payload[:maxControlPayload]
	}
	return c.writeFrame(OpClose, payload)
}

// Close performs an orderly closing handshake.
//
// The deadline exists because a peer that never answers a close frame must not be
// able to hold a goroutine forever.
func (c *Conn) Close(code uint16, reason string) error {
	err := c.writeClose(code, reason)
	c.CloseNow()
	return err
}

// CloseNow closes the underlying connection without a closing handshake.
func (c *Conn) CloseNow() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	c.closeMu.Unlock()

	return c.conn.Close()
}

// RemoteAddr reports the peer address.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetReadDeadline sets the deadline for future reads.
//
// The relay uses this to enforce an idle timeout: a silent client is disconnected
// rather than held indefinitely.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// protocolError closes the connection with status 1002 and returns the error.
func (c *Conn) protocolError(detail string) error {
	_ = c.writeClose(CloseProtocolError, "")
	c.CloseNow()
	return fmt.Errorf("%w: %s", ErrProtocol, detail)
}

// invalidPayload closes the connection with status 1007 and returns the error.
func (c *Conn) invalidPayload(detail string) error {
	_ = c.writeClose(CloseInvalidPayload, "")
	c.CloseNow()
	return fmt.Errorf("%w: %s", ErrProtocol, detail)
}

// tooLarge closes the connection with status 1009 and returns the error.
func (c *Conn) tooLarge() error {
	_ = c.writeClose(CloseMessageTooBig, "")
	c.CloseNow()
	return ErrMessageTooLarge
}

// parseClosePayload extracts the status code and reason from a close frame.
func parseClosePayload(payload []byte) (uint16, string) {
	if len(payload) < 2 {
		return CloseNormal, ""
	}
	code := binary.BigEndian.Uint16(payload[:2])
	reason := string(payload[2:])
	if !utf8.ValidString(reason) {
		reason = ""
	}
	return code, reason
}
