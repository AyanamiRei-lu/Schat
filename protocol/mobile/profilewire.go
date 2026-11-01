package mobile

import (
	"encoding/hex"
	"fmt"
)

// Group nickname announcements on the relay.
//
//	0x07  a group nickname announcement -> the GROUP's mailboxes
//
// It is a distinct type from 0x03 (an MLS group message) even though both are MLS
// PrivateMessages: the receiver must know what it is before it stores anything. A nickname
// that lands in the group's message history is a message nobody sent.
//
// # The relay still does not look
//
// Everything after the token is opaque to the server, which is why this needs no server
// change. That is a property of the relay, not a hope: it has no content-type handling
// anywhere, and the group path has never needed any.

// ContentTypeGroupProfile is the envelope content type of a group nickname announcement.
const ContentTypeGroupProfile = 0x07

// WrapGroupProfile puts a group nickname announcement into a relay envelope.
func WrapGroupProfile(tokenHex string, message []byte) ([]byte, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the delivery token is not hex: %w", err)
	}
	if len(token) != 16 {
		return nil, fmt.Errorf("schat: a delivery token is 16 bytes and this one is %d", len(token))
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("schat: there is no group nickname announcement to send")
	}

	wire := make([]byte, 0, 1+len(token)+len(message))
	wire = append(wire, token...)
	wire = append(wire, ContentTypeGroupProfile)
	wire = append(wire, message...)
	return wire, nil
}

// UnwrapGroupProfile reads a group nickname announcement out of an envelope.
//
// It refuses every other type with a message that names what arrived: "this is a group
// message" is actionable, "unknown content type" is not.
func UnwrapGroupProfile(wire []byte) ([]byte, error) {
	if len(wire) < 17 {
		return nil, fmt.Errorf("schat: an envelope needs a 16-byte token, a type and a payload; "+
			"this one is %d bytes", len(wire))
	}

	switch wire[16] {
	case ContentTypeGroupProfile:
		if len(wire) == 17 {
			return nil, fmt.Errorf("schat: the envelope says it is a group nickname " +
				"announcement and carries nothing after the type")
		}
		return wire[17:], nil
	case ContentTypeGroup:
		return nil, fmt.Errorf("schat: this is a group message, not a group nickname announcement")
	case ContentTypeFrame:
		return nil, fmt.Errorf("schat: this is a one-to-one frame, not a group nickname announcement")
	case ContentTypeHandshake:
		return nil, fmt.Errorf("schat: this is a one-to-one handshake, not a group nickname announcement")
	case ContentTypeProfile:
		return nil, fmt.Errorf("schat: this is a one-to-one nickname announcement, " +
			"not a group one")
	default:
		return nil, fmt.Errorf("schat: unknown envelope content type %#02x", wire[16])
	}
}
