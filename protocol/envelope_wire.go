package protocol

import "fmt"

// The wire form of an envelope, as it travels between a client and the relay.
//
//	token (16) || header (43) || ciphertext
//
// The token is not encrypted and is NOT part of the AEAD's associated data. It is a
// routing label the sender chooses; the recipient's own ratchet state is what
// authenticates the rest of the frame. A relay that rewrote the token would misdeliver
// the envelope, which is a denial of service rather than a compromise — and it cannot
// gain anything by it, because the token carries no identity (SCHAT.md section 4.7).
//
// TokenSize is declared in token.go.

// Marshal encodes an envelope into the bytes the relay carries.
func (e *Envelope) Marshal() []byte {
	out := make([]byte, 0, TokenSize+HeaderSize+len(e.Ciphertext))
	out = append(out, e.Token[:]...)
	out = append(out, e.Header.Marshal()...)
	out = append(out, e.Ciphertext...)
	return out
}

// UnmarshalEnvelope decodes the relay's wire form.
//
// Every bound is checked before slicing. This parses bytes that arrived over a network
// from a party that has not yet been authenticated, so a short or malformed buffer must
// produce an error rather than a panic inside a client.
func UnmarshalEnvelope(b []byte) (*Envelope, error) {
	if len(b) < TokenSize+HeaderSize {
		return nil, fmt.Errorf("%w: envelope needs at least %d bytes, got %d",
			ErrShortBuffer, TokenSize+HeaderSize, len(b))
	}

	var e Envelope
	copy(e.Token[:], b[:TokenSize])

	header, err := UnmarshalHeader(b[TokenSize : TokenSize+HeaderSize])
	if err != nil {
		return nil, err
	}
	e.Header = header

	// Copied rather than aliased: the caller's buffer is usually a network read buffer
	// that will be reused immediately.
	e.Ciphertext = append([]byte(nil), b[TokenSize+HeaderSize:]...)

	return &e, nil
}
