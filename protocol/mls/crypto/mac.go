package crypto

// MAC computes the message authentication code MLS means when it writes MAC(key, value):
// HMAC under the suite's hash function.
//
// It is written as a named function rather than left for callers to spell out because the
// identity it rests on is easy to get wrong in either direction. HKDF-Extract(salt, ikm) is
// defined as HMAC(salt, ikm) — the salt IS the HMAC key — so this is exactly Extract with the
// key in the salt position. Writing `Extract` at a call site that means "MAC" invites the
// next reader to "fix" the argument order, and the result would be a MAC under the wrong key:
// self-consistent, verifiable by the same wrong code, and rejected by every other
// implementation.
func MAC(key, value []byte, suite CipherSuite) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyMACKey
	}
	return Extract(key, value, suite)
}

// ErrEmptyMACKey is returned rather than producing a MAC under a zero-length key, which would
// silently authenticate with a key an attacker can guess.
var ErrEmptyMACKey = macError("mls/crypto: a MAC needs a key")

type macError string

func (e macError) Error() string { return string(e) }
