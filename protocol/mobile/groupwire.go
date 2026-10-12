package mobile

import (
	"encoding/hex"
	"fmt"
)

// Group frames on the relay (see docs/RELAY-API.md sections 2.3 and 2.4).
//
// An envelope is token(16) ‖ content type(1) ‖ payload. The content type is what tells the
// receiving client what the payload is:
//
//	0x01  an SCS-1 frame (a one-to-one message)
//	0x02  an SCS-1 handshake
//	0x03  an MLS group message
//
// # The relay does not look at it
//
// The server treats everything after the token as opaque bytes: it routes by token and never
// inspects the type. That was checked rather than assumed — there is no content-type handling
// anywhere in the server — and it is why group messages need no server change at all.
//
// # Why a group frame is not a one-to-one frame with a different type
//
// A one-to-one frame's payload is protected by SCS-1's double ratchet, which two members share.
// A group message is protected by an MLS epoch, which any number of members share, and a member
// that received one could not decrypt it with the other. Keeping the types distinct means a
// client can tell which machinery to reach for BEFORE it tries, and a mis-delivered message
// fails as "this is not for you" rather than as a decryption error.

// ContentTypeGroup is the envelope content type of an MLS group message.
const ContentTypeGroup = 0x03

// WrapGroup puts a group message into a relay envelope for a delivery token.
func WrapGroup(tokenHex string, message []byte) ([]byte, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the delivery token is not hex: %w", err)
	}
	if len(token) != 16 {
		return nil, fmt.Errorf("schat: a delivery token is 16 bytes and this one is %d", len(token))
	}
	if len(message) == 0 {
		return nil, fmt.Errorf("schat: there is no group message to send")
	}

	wire := make([]byte, 0, 1+len(token)+len(message))
	wire = append(wire, token...)
	wire = append(wire, ContentTypeGroup)
	wire = append(wire, message...)
	return wire, nil
}

// UnwrapGroup reads a group message out of an envelope.
//
// It refuses an envelope of another type rather than returning its payload: a caller that asked
// for a group message and received a one-to-one frame should be told so, because the two are
// protected by different machinery and the payload would be meaningless to it.
func UnwrapGroup(wire []byte) ([]byte, error) {
	if len(wire) < 17 {
		return nil, fmt.Errorf("schat: an envelope needs a 16-byte token, a type and a payload; "+
			"this one is %d bytes", len(wire))
	}

	switch wire[16] {
	case ContentTypeGroup:
		if len(wire) == 17 {
			return nil, fmt.Errorf("schat: the envelope says it is a group message and carries " +
				"nothing after the type")
		}
		return wire[17:], nil
	case 0x01:
		return nil, fmt.Errorf("schat: this is a one-to-one frame, not a group message")
	case 0x02:
		return nil, fmt.Errorf("schat: this is a one-to-one handshake, not a group message")
	default:
		return nil, fmt.Errorf("schat: unknown envelope content type %#02x", wire[16])
	}
}
