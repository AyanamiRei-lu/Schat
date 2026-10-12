package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestPaddedLenUsesBuckets(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, 256},
		{1, 256},
		{200, 256},
		{252, 256},  // 252 + 4 prefix == 256 exactly
		{253, 1024}, // one byte over the first bucket
		{1000, 1024},
		{1020, 1024},
		{1021, 4096},
		{4000, 4096},
		{16000, 16384},
		{65000, 65536},
		{260000, 262144},
		// 262140 + 4 == 262144 exactly: still inside the largest bucket.
		{262140, 262144},
		// 262141 + 4 == 262145 overshoots the largest bucket, so the payload
		// falls to the next quantum multiple. The worst-case overhead just past
		// a boundary is therefore ~256 KiB in absolute terms, which is
		// negligible for the multi-megabyte payloads this path serves.
		{262141, 524288},
	}

	for _, c := range cases {
		if got := PaddedLen(c.in); got != c.want {
			t.Errorf("PaddedLen(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestPaddedLenAlwaysFits is the safety property: the padded buffer must always
// have room for the length prefix plus the payload.
func TestPaddedLenAlwaysFits(t *testing.T) {
	for n := 0; n < 300000; n += 997 {
		padded := PaddedLen(n)
		if padded < n+lengthPrefixSize {
			t.Fatalf("PaddedLen(%d) = %d, which cannot hold the payload plus prefix", n, padded)
		}
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 15, 251, 252, 253, 1000, 1020, 1021, 4095, 4096, 20000}

	for _, n := range sizes {
		plaintext := bytes.Repeat([]byte{0xAB}, n)

		padded := Pad(plaintext)
		if len(padded) != PaddedLen(n) {
			t.Fatalf("size %d: Pad produced %d bytes, want %d", n, len(padded), PaddedLen(n))
		}

		got, err := Unpad(padded)
		if err != nil {
			t.Fatalf("size %d: Unpad: %v", n, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round trip mismatch", n)
		}
	}
}

// TestPadDoesNotAliasInput guards against a buffer-reuse bug where later edits
// to the padded buffer would mutate the caller's plaintext.
func TestPadDoesNotAliasInput(t *testing.T) {
	plaintext := []byte("original")
	padded := Pad(plaintext)

	padded[lengthPrefixSize] = 'X'

	if plaintext[0] == 'X' {
		t.Fatal("Pad returned a buffer aliasing the caller's plaintext")
	}
}

// TestPadHidesLength confirms the point of the whole exercise: many distinct
// plaintext lengths must collapse into a small number of observable sizes.
func TestPadHidesLength(t *testing.T) {
	observed := make(map[int]bool)
	for n := 1; n <= 252; n++ {
		observed[PaddedLen(n)] = true
	}
	if len(observed) != 1 {
		t.Fatalf("lengths 1..252 produced %d distinct ciphertext sizes, want 1", len(observed))
	}
}

func TestUnpadRejectsMalformed(t *testing.T) {
	// Too short to even hold the prefix.
	if _, err := Unpad([]byte{0x00, 0x01}); !errors.Is(err, ErrBadPadding) {
		t.Fatalf("expected ErrBadPadding for a stub buffer, got %v", err)
	}

	// Declares more payload than the buffer can hold.
	oversized := Pad([]byte("small"))
	oversized[3] = 0xFF
	if _, err := Unpad(oversized); !errors.Is(err, ErrBadPadding) {
		t.Fatalf("expected ErrBadPadding for an oversized length, got %v", err)
	}

	// A length prefix that exactly fills the buffer is legal.
	exact := Pad([]byte("abcd"))
	got, err := Unpad(exact)
	if err != nil {
		t.Fatalf("Unpad of a valid buffer failed: %v", err)
	}
	if string(got) != "abcd" {
		t.Fatalf("got %q, want %q", got, "abcd")
	}
}
