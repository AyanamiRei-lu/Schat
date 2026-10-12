package protocol

import (
	"encoding/binary"
	"fmt"
)

// Length hiding (SCHAT.md sections 5.4 and 6.2).
//
// Encrypting a message but leaving its exact length visible leaks a surprising
// amount: a 12-byte message is "ok", a 40-byte message is "I'll be there at
// eight", and a 3 KB message is the address. SCS-1 pads every payload up to one
// of a small set of length buckets so that the ciphertext length only reveals
// the bucket, not the content size.
//
// Layout of a padded payload:
//
//	offset 0        4 bytes   big-endian length of the real plaintext
//	offset 4        N bytes   the plaintext
//	offset 4+N      rest      zero padding to the bucket boundary
//
// The length prefix is inside the authenticated region, so an attacker cannot
// truncate or extend a payload without breaking the AEAD tag.

// lengthPrefixSize is the big-endian plaintext length prefix.
const lengthPrefixSize = 4

// lengthBuckets are the permitted padded sizes, in bytes. They roughly
// quadruple so that the worst-case overhead stays near 4x while the number of
// distinguishable sizes stays small.
var lengthBuckets = []int{256, 1024, 4096, 16384, 65536, 262144}

// bucketQuantum is the granularity used for payloads larger than the largest
// bucket. Rounding to a coarse quantum still hides small length differences
// while keeping memory overhead bounded for multi-megabyte payloads.
const bucketQuantum = 262144

// PaddedLen returns the padded length that Pad would produce for a plaintext of
// n bytes. It is exposed so that callers can allocate exactly once and so that
// tests can assert the bucketing behaviour without allocating.
func PaddedLen(n int) int {
	if n < 0 {
		return 0
	}
	need := n + lengthPrefixSize
	for _, b := range lengthBuckets {
		if need <= b {
			return b
		}
	}
	// Beyond the largest bucket, round up to the next quantum multiple.
	rem := need % bucketQuantum
	if rem == 0 {
		return need
	}
	return need + (bucketQuantum - rem)
}

// Pad returns a new buffer holding plaintext, prefixed with its length and
// zero-padded to the next bucket boundary.
//
// The returned slice shares no memory with plaintext.
func Pad(plaintext []byte) []byte {
	total := PaddedLen(len(plaintext))
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[:lengthPrefixSize], uint32(len(plaintext)))
	copy(out[lengthPrefixSize:], plaintext)
	return out
}

// Unpad reverses Pad.
//
// It validates the length prefix against the buffer it was given and returns
// ErrBadPadding rather than panicking on malformed input. Note that AEAD
// authentication is the real integrity guarantee; this check exists to keep a
// tampered-but-authenticated-in-another-context buffer from causing a slice
// out of range.
func Unpad(padded []byte) ([]byte, error) {
	if len(padded) < lengthPrefixSize {
		return nil, fmt.Errorf("%w: payload shorter than length prefix", ErrBadPadding)
	}
	n := int(binary.BigEndian.Uint32(padded[:lengthPrefixSize]))
	body := padded[lengthPrefixSize:]
	if n < 0 || n > len(body) {
		return nil, fmt.Errorf("%w: declared length %d exceeds available %d",
			ErrBadPadding, n, len(body))
	}
	out := make([]byte, n)
	copy(out, body[:n])
	return out, nil
}
