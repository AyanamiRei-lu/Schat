package schedule

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// PSK secret computation (RFC 9420 section 8.4).
//
// # The algorithm, verbatim from the specification
//
//	psk_extracted_[i] = KDF.Extract(0, psk_[i])
//	psk_input_[i]     = ExpandWithLabel(psk_extracted_[i], "derived psk", PSKLabel, KDF.Nh)
//
//	psk_secret_[0] = 0
//	psk_secret_[i] = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
//	psk_secret     = psk_secret_[n]
//
// where 0 is the all-zero vector of length KDF.Nh, and
//
//	struct {
//	    PreSharedKeyID id;
//	    uint16 index;
//	    uint16 count;
//	} PSKLabel;
//
// # Two things a reader will get wrong, and this file did
//
// The first version of this code chained plain extractions and stopped there. That is not
// the algorithm: each PSK is first extracted against a zero vector, then run through
// ExpandWithLabel under the label "derived psk", and only then chained. The expansion is
// what binds a PSK to its identity and to its position in the list.
//
// The second, and worse, was an explicit comment in that version stating that a PSK's id and
// nonce "are NOT part of this computation". They are: PSKLabel carries the whole
// PreSharedKeyID, and the nonce is precisely what makes the same PSK produce a different
// input each time it is injected. The vector file gives three fields per PSK — id, secret
// and nonce — and the first version used only the middle one while asserting the other two
// were irrelevant.
//
// # The empty case is a definition
//
// With no PSKs the secret is psk_secret_[0], the all-zero vector. No arrangement of
// extractions can produce zeros, so this is stated rather than derived.

// PSK is one pre-shared key together with the identity it is known by.
type PSK struct {
	// ID is the opaque psk_id of an external PSK.
	ID []byte

	// Secret is the PSK itself.
	Secret []byte

	// Nonce is the psk_nonce, which must be fresh for each injection.
	Nonce []byte
}

// PSKSecret derives the pre-shared key secret from the PSKs of one epoch, in proposal order.
func PSKSecret(psks []PSK, suite crypto.CipherSuite) ([]byte, error) {
	hashSize := suite.HashSize()
	if hashSize == 0 {
		return nil, fmt.Errorf("mls/schedule: unsupported cipher suite %#04x", uint16(suite))
	}

	zeros := make([]byte, hashSize)

	// psk_secret_[0] = 0, and with no PSKs that is the answer.
	secret := make([]byte, hashSize)

	for i, psk := range psks {
		extracted, err := crypto.Extract(zeros, psk.Secret, suite)
		if err != nil {
			return nil, fmt.Errorf("mls/schedule: extracting PSK %d: %w", i, err)
		}

		label, err := marshalPSKLabel(psk, uint16(i), uint16(len(psks)))
		if err != nil {
			return nil, err
		}

		input, err := crypto.ExpandWithLabel(extracted, "derived psk", label, hashSize, suite)
		if err != nil {
			return nil, fmt.Errorf("mls/schedule: expanding PSK %d: %w", i, err)
		}

		// KDF.Extract(psk_input_[i], psk_secret_[i]) — the new input is the salt and the
		// running value is the input keying material, which is the order the specification
		// writes and the order the vectors require.
		secret, err = crypto.Extract(input, secret, suite)
		if err != nil {
			return nil, fmt.Errorf("mls/schedule: chaining PSK %d: %w", i, err)
		}
	}

	return secret, nil
}

// PSKTypeExternal is the psktype of a PSK supplied by the application.
//
// Resumption PSKs (type 2) carry a usage, a group id and an epoch instead of an opaque id;
// they are not implemented here because no vector in this repository exercises them and
// SCHAT does not yet resume groups. A resumption PSK reaching this function is an error
// rather than something silently encoded as external.
const PSKTypeExternal = 1

// marshalPSKLabel encodes PSKLabel for one PSK.
//
// The index and count are what tell a receiver which PSK in the list this expansion belongs
// to, which is why they must be the position in the proposal list and the length of that
// list rather than anything derived from the key material.
func marshalPSKLabel(psk PSK, index, count uint16) ([]byte, error) {
	if len(psk.ID) == 0 {
		return nil, fmt.Errorf("mls/schedule: a PSK must carry its id")
	}
	if len(psk.Nonce) == 0 {
		return nil, fmt.Errorf("mls/schedule: a PSK must carry its nonce")
	}

	w := mlstls.NewWriter(len(psk.ID) + len(psk.Nonce) + 8)
	w.Uint8(PSKTypeExternal)
	w.Opaque(psk.ID)
	w.Opaque(psk.Nonce)
	w.Uint16(index)
	w.Uint16(count)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
