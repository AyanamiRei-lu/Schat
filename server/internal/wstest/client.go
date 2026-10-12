// Package wstest provides a minimal WebSocket client used by the relay's tests.
//
// It lives in its own package rather than in a _test.go file because several
// packages need it, and it deliberately does NOT reuse the server-side framing
// code: a client written independently from RFC 6455 is what makes the tests
// meaningful. If both sides shared one misreading of the specification, the tests
// would agree with the bug and pass.
//
// It is not part of the shipped server. Nothing outside test files imports it.
package wstest

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// Opcodes used by the tests.
const (
	OpText   byte = 0x1
	OpBinary byte = 0x2
	OpClose  byte = 0x8
	OpPing   byte = 0x9
	OpPong   byte = 0xA
)

const handshakeGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Client is a connected test client.
type Client struct {
	conn net.Conn
	br   *bufio.Reader
}

// Dial opens a WebSocket connection to a ws:// URL.
func Dial(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("wstest: parsing %q: %w", rawURL, err)
	}

	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("wstest: dialling %s: %w", u.Host, err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)

	path := u.Path
	if path == "" {
		path = "/"
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, key)
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}

	c := &Client{conn: conn, br: bufio.NewReader(conn)}

	status, err := c.br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("wstest: reading handshake status: %w", err)
	}
	if !strings.Contains(status, "101") {
		conn.Close()
		return nil, fmt.Errorf("wstest: expected 101, got %q", strings.TrimSpace(status))
	}

	headers := map[string]string{}
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}

	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, handshakeGUID)
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if headers["sec-websocket-accept"] != want {
		conn.Close()
		return nil, fmt.Errorf("wstest: bad Sec-WebSocket-Accept %q", headers["sec-websocket-accept"])
	}

	return c, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// SetReadDeadline sets the deadline for subsequent reads.
func (c *Client) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// WriteText sends a text message.
func (c *Client) WriteText(payload []byte) error { return c.writeFrame(OpText, payload) }

// WriteBinary sends a binary message.
func (c *Client) WriteBinary(payload []byte) error { return c.writeFrame(OpBinary, payload) }

// WritePing sends a ping frame.
func (c *Client) WritePing(payload []byte) error { return c.writeFrame(OpPing, payload) }

// writeFrame always masks, as RFC 6455 requires of clients.
func (c *Client) writeFrame(opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}

	switch {
	case len(payload) <= 125:
		header = append(header, 0x80|byte(len(payload)))
	case len(payload) <= 0xFFFF:
		header = append(header, 0x80|126)
		header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	default:
		header = append(header, 0x80|127)
		header = binary.BigEndian.AppendUint64(header, uint64(len(payload)))
	}

	var key [4]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	header = append(header, key[:]...)

	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ key[i&3]
	}

	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	if len(masked) > 0 {
		if _, err := c.conn.Write(masked); err != nil {
			return err
		}
	}
	return nil
}

// ReadMessage returns the next text or binary message, skipping control frames.
//
// A close frame is returned as an error.
func (c *Client) ReadMessage() (opcode byte, payload []byte, err error) {
	for {
		op, frame, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case OpPing, OpPong:
			continue
		case OpClose:
			return 0, nil, fmt.Errorf("wstest: server closed the connection")
		default:
			return op, frame, nil
		}
	}
}

// ReadText reads the next text message.
func (c *Client) ReadText() (string, error) {
	op, payload, err := c.ReadMessage()
	if err != nil {
		return "", err
	}
	if op != OpText {
		return "", fmt.Errorf("wstest: expected a text message, got opcode %#x", op)
	}
	return string(payload), nil
}

// ReadBinary reads the next binary message.
func (c *Client) ReadBinary() ([]byte, error) {
	op, payload, err := c.ReadMessage()
	if err != nil {
		return nil, err
	}
	if op != OpBinary {
		return nil, fmt.Errorf("wstest: expected a binary message, got opcode %#x", op)
	}
	return payload, nil
}

func (c *Client) readFrame() (opcode byte, payload []byte, err error) {
	var header [2]byte
	if _, err := io.ReadFull(c.br, header[:]); err != nil {
		return 0, nil, err
	}
	opcode = header[0] & 0x0F

	if header[1]&0x80 != 0 {
		return 0, nil, fmt.Errorf("wstest: server frame was masked")
	}

	length := int64(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext[:]))
	}

	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return 0, nil, err
		}
	}
	return opcode, payload, nil
}

// ReadWithTimeout reads the next message, failing if nothing arrives in time.
//
// It exists so that tests assert on absence without sleeping blindly: a test that
// expects no message must fail promptly rather than hang.
func (c *Client) ReadWithTimeout(timeout time.Duration) (byte, []byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, nil, err
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	return c.ReadMessage()
}

// WaitForClose asserts that the peer closes the connection within the timeout.
func (c *Client) WaitForClose(timeout time.Duration) error {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	for {
		_, _, err := c.ReadMessage()
		if err != nil {
			return nil
		}
	}
}

// ContextDial is a convenience for tests that want a cancellable dial.
func ContextDial(ctx context.Context, rawURL string) (*Client, error) {
	type result struct {
		client *Client
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		client, err := Dial(rawURL)
		ch <- result{client, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.client, r.err
	}
}
