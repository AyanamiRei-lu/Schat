package tls

import (
	"bytes"
	"errors"
	"testing"
)

// The three worked examples RFC 9420 section 2.1.2 gives for the length prefix. If these
// do not decode to these values, nothing above this package can match a test vector.
func TestVarintMatchesTheRFCsWorkedExamples(t *testing.T) {
	cases := []struct {
		encoded []byte
		value   uint32
	}{
		{[]byte{0x25}, 37},
		{[]byte{0x7b, 0xbd}, 15293},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333},
	}

	for _, c := range cases {
		r := NewReader(c.encoded)
		got, err := r.Varint()
		if err != nil {
			t.Errorf("%x: %v", c.encoded, err)
			continue
		}
		if got != c.value {
			t.Errorf("%x decoded to %d, want %d", c.encoded, got, c.value)
		}
		if !r.Empty() {
			t.Errorf("%x left %d bytes unread", c.encoded, r.Remaining())
		}

		// ...and encoding must reproduce the same bytes, not merely the same value.
		w := NewWriter(4)
		w.Varint(c.value)
		if err := w.Err(); err != nil {
			t.Errorf("encoding %d: %v", c.value, err)
			continue
		}
		if !bytes.Equal(w.Bytes(), c.encoded) {
			t.Errorf("%d encoded to %x, want %x", c.value, w.Bytes(), c.encoded)
		}
	}
}

// The boundaries between encodings are where an off-by-one lives, so they are pinned by
// both the value and the encoded length.
func TestVarintBoundaries(t *testing.T) {
	cases := []struct {
		value  uint32
		length int
	}{
		{0, 1},
		{1, 1},
		{63, 1},
		{64, 2},
		{255, 2},
		{16383, 2},
		{16384, 4},
		{1 << 20, 4},
		{MaxVarint, 4},
	}

	for _, c := range cases {
		w := NewWriter(4)
		w.Varint(c.value)
		if err := w.Err(); err != nil {
			t.Errorf("%d: %v", c.value, err)
			continue
		}
		if len(w.Bytes()) != c.length {
			t.Errorf("%d encoded in %d bytes, want %d", c.value, len(w.Bytes()), c.length)
		}

		got, err := NewReader(w.Bytes()).Varint()
		if err != nil {
			t.Errorf("%d: decoding %x: %v", c.value, w.Bytes(), err)
			continue
		}
		if got != c.value {
			t.Errorf("%x decoded to %d, want %d", w.Bytes(), got, c.value)
		}
	}
}

// RFC 9420 requires the shortest encoding and requires decoders to REJECT anything longer.
// QUIC, which this is adapted from, allows non-minimal encodings — so this is the one place
// where copying QUIC naively would produce a conformant-looking implementation that fails
// every test vector that happens to contain a small length.
func TestNonMinimalVarintsAreRejected(t *testing.T) {
	cases := map[string][]byte{
		"37 in two bytes":     {0x40, 0x25},
		"37 in four bytes":    {0x80, 0x00, 0x00, 0x25},
		"63 in two bytes":     {0x40, 0x3f},
		"63 in four bytes":    {0x80, 0x00, 0x00, 0x3f},
		"16383 in four bytes": {0x80, 0x00, 0x3f, 0xff},
		"zero in two bytes":   {0x40, 0x00},
		"zero in four bytes":  {0x80, 0x00, 0x00, 0x00},
		"16384 needs four":    {0x80, 0x00, 0x40, 0x00}, // minimal, must be ACCEPTED
	}

	for name, encoded := range cases {
		r := NewReader(encoded)
		value, err := r.Varint()

		if name == "16384 needs four" {
			if err != nil || value != 16384 {
				t.Errorf("%s: got (%d, %v), want (16384, nil)", name, value, err)
			}
			continue
		}

		if !errors.Is(err, ErrNonMinimalVarint) {
			t.Errorf("%s (%x): got (%d, %v), want ErrNonMinimalVarint", name, encoded, value, err)
		}
	}
}

func TestVarintRejectsTheReservedPrefix(t *testing.T) {
	for _, first := range []byte{0xc0, 0xd5, 0xff} {
		r := NewReader([]byte{first, 0x00, 0x00, 0x00})
		if _, err := r.Varint(); !errors.Is(err, ErrInvalidVarintPrefix) {
			t.Errorf("prefix %#x: got %v, want ErrInvalidVarintPrefix", first, err)
		}
	}
}

func TestVarintTruncationIsAnError(t *testing.T) {
	cases := map[string][]byte{
		"nothing":            {},
		"half of two bytes":  {0x40},
		"half of four bytes": {0x80, 0x01},
		"three of four":      {0x9d, 0x7f, 0x3e},
	}

	for name, encoded := range cases {
		if _, err := NewReader(encoded).Varint(); !errors.Is(err, ErrTruncated) {
			t.Errorf("%s (%x): got %v, want ErrTruncated", name, encoded, err)
		}
	}
}

func TestVarintRefusesValuesItCannotEncode(t *testing.T) {
	w := NewWriter(8)
	w.Varint(1 << 30) // one past the maximum
	if !errors.Is(w.Err(), ErrVarintTooLarge) {
		t.Fatalf("got %v, want ErrVarintTooLarge", w.Err())
	}
}

func TestIntegerWidths(t *testing.T) {
	w := NewWriter(16)
	w.Uint8(0xab)
	w.Uint16(0x1234)
	w.Uint24(0x010203)
	w.Uint32(0xdeadbeef)
	w.Uint64(0x0123456789abcdef)
	if err := w.Err(); err != nil {
		t.Fatalf("encoding: %v", err)
	}

	want := []byte{
		0xab,
		0x12, 0x34,
		0x01, 0x02, 0x03,
		0xde, 0xad, 0xbe, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("got %x, want %x", w.Bytes(), want)
	}

	r := NewReader(w.Bytes())
	if v, _ := r.Uint8(); v != 0xab {
		t.Errorf("uint8: %#x", v)
	}
	if v, _ := r.Uint16(); v != 0x1234 {
		t.Errorf("uint16: %#x", v)
	}
	if v, _ := r.Uint24(); v != 0x010203 {
		t.Errorf("uint24: %#x", v)
	}
	if v, _ := r.Uint32(); v != 0xdeadbeef {
		t.Errorf("uint32: %#x", v)
	}
	if v, _ := r.Uint64(); v != 0x0123456789abcdef {
		t.Errorf("uint64: %#x", v)
	}
	if err := r.Finish(); err != nil {
		t.Errorf("finish: %v", err)
	}
}

func TestUint24RefusesValuesThatDoNotFit(t *testing.T) {
	w := NewWriter(3)
	w.Uint24(1 << 24)
	if w.Err() == nil {
		t.Fatal("a value above 2^24-1 was accepted into a uint24")
	}
}

func TestOpaqueRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 1000, 16384} {
		payload := bytes.Repeat([]byte{0x5a}, size)

		w := NewWriter(size + 4)
		w.Opaque(payload)
		if err := w.Err(); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}

		got, err := NewReader(w.Bytes()).Opaque()
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: payload did not survive", size)
		}
	}
}

// A nested structure, to show the length prefixes come out right when they are not flat.
func TestNestedVectorsRoundTrip(t *testing.T) {
	type inner struct {
		id   uint32
		name []byte
	}
	type outer struct {
		version  uint16
		items    []inner
		optional []byte
	}

	want := outer{
		version: 0x0001,
		items: []inner{
			{id: 1, name: []byte("alice")},
			{id: 16384, name: nil},
			{id: 300000, name: bytes.Repeat([]byte("x"), 100)},
		},
	}

	w := NewWriter(64)
	w.Uint16(want.version)
	w.Vector(func(w *Writer) error {
		for _, item := range want.items {
			w.Uint32(item.id)
			w.Opaque(item.name)
		}
		return nil
	})
	w.Optional(nil) // absent

	if err := w.Err(); err != nil {
		t.Fatalf("encoding: %v", err)
	}

	var got outer
	err := Decode(w.Bytes(), func(r *Reader) error {
		var err error
		if got.version, err = r.Uint16(); err != nil {
			return err
		}
		if err := r.Vector(func(r *Reader) error {
			for !r.Empty() {
				var item inner
				if item.id, err = r.Uint32(); err != nil {
					return err
				}
				if item.name, err = r.Opaque(); err != nil {
					return err
				}
				got.items = append(got.items, item)
			}
			return nil
		}); err != nil {
			return err
		}
		present, err := r.Optional(func(r *Reader) error {
			got.optional, err = r.Opaque()
			return err
		})
		if err != nil {
			return err
		}
		if present {
			return errors.New("the absent optional was reported as present")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if got.version != want.version || len(got.items) != len(want.items) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want.items {
		if got.items[i].id != want.items[i].id {
			t.Errorf("item %d id: %d, want %d", i, got.items[i].id, want.items[i].id)
		}
		if !bytes.Equal(got.items[i].name, want.items[i].name) {
			t.Errorf("item %d name: %x, want %x", i, got.items[i].name, want.items[i].name)
		}
	}
}

func TestOptionalPresenceByteMustBeZeroOrOne(t *testing.T) {
	for _, present := range []byte{2, 3, 0x80, 0xff} {
		r := NewReader([]byte{present})
		if _, err := r.Optional(func(*Reader) error { return nil }); !errors.Is(err, ErrInvalidOptionalPresence) {
			t.Errorf("presence %#x: got %v, want ErrInvalidOptionalPresence", present, err)
		}
	}
}

func TestOptionalPresentAndAbsentAreDistinct(t *testing.T) {
	// Absent.
	w := NewWriter(2)
	w.Optional(nil)
	if !bytes.Equal(w.Bytes(), []byte{0x00}) {
		t.Fatalf("absent encoded as %x", w.Bytes())
	}

	// Present but empty: a different encoding, and some MLS fields distinguish them.
	w = NewWriter(2)
	w.Optional(func(w *Writer) error { return nil })
	if !bytes.Equal(w.Bytes(), []byte{0x01}) {
		t.Fatalf("present-and-empty encoded as %x", w.Bytes())
	}
}

func TestTrailingBytesAreRejected(t *testing.T) {
	// A whole message with one byte too many.
	err := Decode([]byte{0x01, 0x02}, func(r *Reader) error {
		_, err := r.Uint8()
		return err
	})
	if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("trailing byte: got %v, want ErrTrailingBytes", err)
	}

	// A vector whose body does not consume exactly its declared length.
	r := NewReader([]byte{0x02, 0xaa, 0xbb})
	err = r.Vector(func(r *Reader) error {
		_, err := r.Uint8()
		return err
	})
	if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("short vector body: got %v, want ErrTrailingBytes", err)
	}
}

func TestAVectorLongerThanTheInputIsRefusedWithoutAllocating(t *testing.T) {
	// A four-byte prefix can claim 1 GiB. A decoder that trusts it and allocates has handed
	// any peer a trivial memory-exhaustion attack.
	hostile := []byte{0xbf, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03}

	r := NewReader(hostile)
	err := r.Vector(func(*Reader) error { return nil })
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}

	// The error must have been reached without a gigabyte-sized allocation. Measuring the
	// bytes rather than the count is what makes this assertion mean anything.
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewReader(hostile).Vector(func(*Reader) error { return nil })
		}
	})
	if allocated := result.AllocedBytesPerOp(); allocated > 4096 {
		t.Errorf("decoding a 1 GiB length claim allocated %d bytes per operation", allocated)
	}
}

// Decoding arbitrary bytes must never panic. The seed corpus runs as part of the ordinary
// test suite; `go test -fuzz` extends it.
func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xbf, 0xff, 0xff, 0xff})
	f.Add([]byte{0x40, 0x25})
	f.Add([]byte{0x9d, 0x7f, 0x3e, 0x7d})
	f.Add([]byte{0x01, 0xff, 0x00, 0x01, 0x02, 0x03})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(data)

		// Exercise the whole surface. Every call must return, not panic, and must not read
		// past the end of the input.
		for i := 0; i < 8 && !r.Empty(); i++ {
			switch i % 6 {
			case 0:
				_, _ = r.Varint()
			case 1:
				_, _ = r.Opaque()
			case 2:
				_, _ = r.Uint64()
			case 3:
				_ = r.Vector(func(r *Reader) error {
					_, err := r.Opaque()
					return err
				})
			case 4:
				_, _ = r.Optional(func(r *Reader) error {
					_, err := r.Uint32()
					return err
				})
			case 5:
				_, _ = r.Uint24()
			}
		}

		if r.Remaining() < 0 {
			t.Fatalf("the reader ran past the end of the input")
		}
	})
}

// A short deterministic sweep over the shortest inputs, so the common malformed cases are
// covered even when the fuzzer is not run.
func TestShortInputsNeverPanic(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b += 17 {
			data := []byte{byte(a), byte(b)}
			r := NewReader(data)
			_, _ = r.Varint()
			_, _ = r.Opaque()
			_, _ = r.Uint64()
			if r.Remaining() < 0 {
				t.Fatalf("reader ran past the end on %x", data)
			}
		}
	}
}
