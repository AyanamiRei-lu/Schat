// Package tls implements the MLS presentation language.
//
// # Why this package exists, and why it is separate
//
// MLS describes its messages in the TLS presentation language (RFC 8446, section 3) with
// two additions of its own (RFC 9420, section 2.1): optional values, and vectors whose
// length is a variable-length integer rather than a fixed-width one.
//
// Every MLS structure — KeyPackage, LeafNode, Proposal, Commit, Welcome, GroupInfo, the
// two message framings — is built out of this vocabulary. That makes this the foundation
// the whole of step 6a stands on: if a length prefix here has the wrong width, or a vector
// is read with the wrong bound, then a Commit produced by this code differs from the
// official test vector in a way that is invisible until something refuses to decrypt, and
// the cause could be anywhere in five thousand lines above it.
//
// It is therefore written first, separately, and tested against the worked examples the
// RFC itself provides.
//
// # What it must never do
//
// Decoding is applied to attacker-controlled bytes. Two obligations follow, and both are
// enforced here rather than left to callers:
//
//   - A length prefix must be checked against the bytes actually available BEFORE anything
//     is allocated. A four-byte prefix can claim a gigabyte; a decoder that trusts it and
//     allocates hands any peer a trivial memory-exhaustion attack.
//   - A malformed encoding must produce an error, never a panic. Every read is bounds
//     checked, and there is a fuzz target for it.
package tls

import (
	"errors"
	"fmt"
)

// Errors returned while decoding.
var (
	// ErrTruncated means the input ended before the value did.
	ErrTruncated = errors.New("mls/tls: input ended in the middle of a value")

	// ErrInvalidVarintPrefix means a length prefix used the reserved two-bit value 0b11.
	ErrInvalidVarintPrefix = errors.New("mls/tls: invalid variable-length integer prefix")

	// ErrNonMinimalVarint means a length was encoded in more bytes than necessary.
	//
	// RFC 9420 requires the shortest encoding and requires decoders to reject anything
	// longer. It is stricter than QUIC here, and the difference matters: without it, the
	// same value has several valid encodings, so two implementations can produce different
	// bytes for the same message and no transcript hash would match.
	ErrNonMinimalVarint = errors.New("mls/tls: variable-length integer was not minimally encoded")

	// ErrVarintTooLarge means a value exceeded the 30 bits a length prefix can carry.
	ErrVarintTooLarge = errors.New("mls/tls: variable-length integer exceeds 2^30-1")

	// ErrTrailingBytes means decoding finished with input left over.
	//
	// Always an error rather than something to skip: trailing bytes are how a message
	// carrying one interpretation to a strict parser and another to a lax one is built.
	ErrTrailingBytes = errors.New("mls/tls: unexpected trailing bytes")

	// ErrInvalidOptionalPresence means an optional value's presence byte was neither 0 nor 1.
	ErrInvalidOptionalPresence = errors.New("mls/tls: optional presence byte was not 0 or 1")
)

// MaxVarint is the largest value a length prefix can carry: 2^30-1.
const MaxVarint = (1 << 30) - 1

// Writer builds an MLS-encoded byte string.
//
// The zero value is ready to use. Encoding cannot fail except on a value that does not fit
// its field, which is a programming error rather than a runtime condition — those are
// reported so that a mistake in this package surfaces in its own tests rather than as a
// corrupt message on the wire.
type Writer struct {
	buf []byte
	err error
}

// NewWriter returns a writer with room for the given number of bytes.
func NewWriter(capacity int) *Writer {
	if capacity < 0 {
		// make would panic on a negative capacity, and a caller that computed one has a
		// bug worth surviving rather than crashing on.
		capacity = 0
	}
	return &Writer{buf: make([]byte, 0, capacity)}
}

// Bytes returns the encoded output. It is only meaningful when Err is nil.
func (w *Writer) Bytes() []byte { return w.buf }

// Err reports the first encoding error, if any.
func (w *Writer) Err() error { return w.err }

// Len is the number of bytes written so far.
func (w *Writer) Len() int { return len(w.buf) }

func (w *Writer) Uint8(v uint8) { w.buf = append(w.buf, v) }

func (w *Writer) Uint16(v uint16) {
	w.buf = append(w.buf, byte(v>>8), byte(v))
}

// Uint24 writes a 24-bit big-endian value. Values above 2^24-1 are truncated by the
// compiler's conversion, so the caller's range is checked explicitly.
func (w *Writer) Uint24(v uint32) {
	if v > 0xFFFFFF {
		w.fail(fmt.Errorf("mls/tls: %d does not fit in uint24", v))
		return
	}
	w.buf = append(w.buf, byte(v>>16), byte(v>>8), byte(v))
}

func (w *Writer) Uint32(v uint32) {
	w.buf = append(w.buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func (w *Writer) Uint64(v uint64) {
	w.buf = append(w.buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Raw writes bytes with no length prefix. Used for fixed-size fields.
func (w *Writer) Raw(b []byte) { w.buf = append(w.buf, b...) }

// Varint writes a variable-length integer as a length prefix.
func (w *Writer) Varint(v uint32) {
	if v > MaxVarint {
		w.fail(fmt.Errorf("%w: %d", ErrVarintTooLarge, v))
		return
	}

	switch {
	case v < 1<<6:
		w.buf = append(w.buf, byte(v))
	case v < 1<<14:
		w.buf = append(w.buf, 0x40|byte(v>>8), byte(v))
	default:
		w.buf = append(w.buf, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// Opaque writes a length-prefixed byte string.
func (w *Writer) Opaque(b []byte) {
	w.Varint(uint32(len(b)))
	w.Raw(b)
}

// Vector writes a length-prefixed structure.
//
// The body is written into a scratch buffer first, because the prefix cannot be emitted
// until the body's length is known. That is also why a vector's length is never computed
// by hand at the call site: the two places a hand-computed length can be wrong — forgetting
// a nested prefix, counting the wrong field — both disappear.
func (w *Writer) Vector(write func(*Writer) error) {
	sub := &Writer{}
	if err := write(sub); err != nil {
		w.fail(err)
		return
	}
	if sub.err != nil {
		w.fail(sub.err)
		return
	}
	w.Opaque(sub.buf)
}

// Optional writes a value that may be absent.
//
// A nil write function and a present-but-empty value are different: the first emits the
// presence byte 0, the second emits 1 followed by the value. Some MLS fields distinguish
// them, so the caller chooses rather than the writer guessing.
func (w *Writer) Optional(write func(*Writer) error) {
	if write == nil {
		w.Uint8(0)
		return
	}
	w.Uint8(1)
	sub := &Writer{}
	if err := write(sub); err != nil {
		w.fail(err)
		return
	}
	if sub.err != nil {
		w.fail(sub.err)
		return
	}
	w.Raw(sub.buf)
}

func (w *Writer) fail(err error) {
	if w.err == nil {
		w.err = err
	}
}

// Reader decodes MLS-encoded bytes.
//
// Every method returns an error rather than panicking, and no method reads past the end of
// the buffer, so a Reader over hostile input can only ever produce a value or an error.
type Reader struct {
	buf []byte
	pos int
}

// NewReader returns a reader over b. The slice is not copied; the caller must not modify
// it while the reader is in use.
func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Remaining is the number of bytes not yet read.
func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

// Empty reports whether everything has been read.
func (r *Reader) Empty() bool { return r.pos >= len(r.buf) }

func (r *Reader) Uint8() (uint8, error) {
	if r.Remaining() < 1 {
		return 0, ErrTruncated
	}
	v := r.buf[r.pos]
	r.pos++
	return v, nil
}

func (r *Reader) Uint16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (r *Reader) Uint24() (uint32, error) {
	b, err := r.take(3)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

func (r *Reader) Uint32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func (r *Reader) Uint64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// Raw reads exactly n bytes without a length prefix.
func (r *Reader) Raw(n int) ([]byte, error) { return r.take(n) }

// Varint reads a length prefix.
func (r *Reader) Varint() (uint32, error) {
	if r.Remaining() < 1 {
		return 0, ErrTruncated
	}

	first := r.buf[r.pos]
	prefix := first >> 6
	if prefix == 3 {
		return 0, ErrInvalidVarintPrefix
	}

	length := 1 << prefix
	if r.Remaining() < length {
		return 0, ErrTruncated
	}

	v := uint32(first & 0x3F)
	for i := 1; i < length; i++ {
		v = v<<8 | uint32(r.buf[r.pos+i])
	}
	r.pos += length

	// RFC 9420 requires the shortest encoding and requires a decoder to reject anything
	// longer, using exactly this test.
	if prefix >= 1 && v < 1<<(8*(length/2)-2) {
		return 0, ErrNonMinimalVarint
	}
	return v, nil
}

// Opaque reads a length-prefixed byte string.
func (r *Reader) Opaque() ([]byte, error) {
	n, err := r.Varint()
	if err != nil {
		return nil, err
	}
	return r.take(int(n))
}

// Vector reads a length-prefixed structure and requires it to be consumed exactly.
//
// The length is checked against the bytes available BEFORE the sub-reader is created, so a
// prefix claiming a gigabyte fails immediately instead of allocating. Requiring the body to
// be fully consumed is what stops a vector from smuggling a second interpretation of the
// bytes that follow.
func (r *Reader) Vector(read func(*Reader) error) error {
	n, err := r.Varint()
	if err != nil {
		return err
	}

	body, err := r.take(int(n))
	if err != nil {
		return err
	}

	sub := NewReader(body)
	if err := read(sub); err != nil {
		return err
	}
	if !sub.Empty() {
		return fmt.Errorf("%w: %d bytes left inside a vector", ErrTrailingBytes, sub.Remaining())
	}
	return nil
}

// Optional reads a value that may be absent.
func (r *Reader) Optional(read func(*Reader) error) (bool, error) {
	present, err := r.Uint8()
	if err != nil {
		return false, err
	}
	switch present {
	case 0:
		return false, nil
	case 1:
		if err := read(r); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, ErrInvalidOptionalPresence
	}
}

// Finish checks that everything has been consumed.
func (r *Reader) Finish() error {
	if !r.Empty() {
		return fmt.Errorf("%w: %d bytes left", ErrTrailingBytes, r.Remaining())
	}
	return nil
}

func (r *Reader) take(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("mls/tls: negative length %d", n)
	}
	if r.Remaining() < n {
		return nil, fmt.Errorf("%w: wanted %d bytes, %d remain", ErrTruncated, n, r.Remaining())
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

// Decode runs read over b and requires the whole input to be consumed.
//
// The strict form is the default because MLS messages are exactly one structure: anything
// left over means the sender and this decoder disagree about the format.
func Decode(b []byte, read func(*Reader) error) error {
	r := NewReader(b)
	if err := read(r); err != nil {
		return err
	}
	return r.Finish()
}
