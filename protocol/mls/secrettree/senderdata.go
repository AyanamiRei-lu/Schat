package secrettree

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
)

// The keys that protect a private message's sender data (RFC 9420 section 6.3.2).
//
//	ciphertext_sample = ciphertext[0..KDF.Nh-1]
//
//	sender_data_key   = ExpandWithLabel(sender_data_secret, "key",   ciphertext_sample, AEAD.Nk)
//	sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, AEAD.Nn)
//
// # The sample is the point
//
// The sample is the first KDF.Nh bytes of the CIPHERTEXT OF THE MESSAGE BEING SENT — the very
// bytes this key is about to help produce. That is why the sender data can only be sealed after
// the content is, and why a receiver must decrypt the sender data using a sample taken from the
// ciphertext it received rather than from anything it computes.
//
// Three details here are each easy to get wrong and none of them fails locally:
//
//   - the CONTEXT is the ciphertext sample, not the empty string and not the whole ciphertext;
//   - the LABELS are "key" and "nonce", not anything containing "sender_data";
//   - the LENGTHS are the AEAD's, while the sample's length is the HASH's.
//
// An implementation that got any of them wrong would encrypt and decrypt against itself
// perfectly. The official secret-tree vectors publish a ciphertext and the key and nonce it
// yields, which is what makes these three checkable rather than arguable.

// SenderDataKeyNonce derives the key and nonce that protect the sender data of a private
// message whose content ciphertext is given.
//
// The ciphertext must be at least as long as the hash, because the sample is the first HashSize
// bytes of it: a shorter one has no sample, and padding or truncating would produce a sample
// the sender never used.
func SenderDataKeyNonce(senderDataSecret, ciphertext []byte, suite crypto.CipherSuite) (key, nonce []byte, err error) {
	hashSize := suite.HashSize()
	if hashSize == 0 {
		return nil, nil, fmt.Errorf("mls/secrettree: unsupported cipher suite %#04x", uint16(suite))
	}
	if len(senderDataSecret) != hashSize {
		return nil, nil, fmt.Errorf("mls/secrettree: the sender data secret is %d bytes, want %d",
			len(senderDataSecret), hashSize)
	}
	if len(ciphertext) < hashSize {
		return nil, nil, fmt.Errorf("mls/secrettree: the ciphertext is %d bytes and the sample is "+
			"the first %d, so there is not enough of it to derive from", len(ciphertext), hashSize)
	}

	sample := ciphertext[:hashSize]

	key, err = crypto.ExpandWithLabel(senderDataSecret, "key", sample, suite.AEADKeySize(), suite)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = crypto.ExpandWithLabel(senderDataSecret, "nonce", sample, suite.AEADNonceSize(), suite)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}
