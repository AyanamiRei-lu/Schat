package mobile

import (
	"fmt"
)

// Group welcomes on the relay.
//
// # Why a welcome needs its own content type
//
// A group MESSAGE is delivered to the group's mailboxes, which every member derives from the
// epoch. A member being ADDED is not in the epoch yet, so it cannot derive them — its welcome
// has to go to a mailbox it can already reach, and the only such mailbox is the one derived from
// its identity, the same one a one-to-one handshake arrives in.
//
// So the two travel by different routes, and the content type is what tells the receiver which
// it has:
//
//	0x03  a group message, for a group the receiver is already in
//	0x04  a group welcome, for a group the receiver is about to join
//
// The distinction is not cosmetic. A client that treated a welcome as a message would look for a
// group it does not have and report that the message belongs to nothing; a client that treated a
// message as a welcome would try to join a group it is already in.
//
// # The shape is the same, and so is the code path
//
// A welcome envelope is byte-for-byte what a group envelope is, with one different byte. It is
// built by rewriting that byte rather than by repeating the token checks, so the two routes
// cannot drift apart in how they validate a token — a drift that would show up as welcomes
// being routed to a mailbox nobody reads.

// ContentTypeGroupWelcome is the envelope content type of an MLS Welcome.
const ContentTypeGroupWelcome = 0x04

// WrapGroupWelcome puts a Welcome into a relay envelope for a delivery token.
//
// The token is the JOINER's identity-derived mailbox, not the group's: it cannot reach the
// group's mailboxes, because it is not in the group yet.
func WrapGroupWelcome(tokenHex string, welcome []byte) ([]byte, error) {
	wire, err := WrapGroup(tokenHex, welcome)
	if err != nil {
		return nil, err
	}
	wire[16] = ContentTypeGroupWelcome
	return wire, nil
}

// UnwrapGroupWelcome reads a Welcome out of an envelope.
//
// It refuses an envelope of another type rather than returning its payload. A group MESSAGE and
// a welcome are handled by completely different code — one is opened with an epoch secret, the
// other is what PRODUCES the epoch secret — so handing one to the other's path produces an error
// that describes the wrong thing.
func UnwrapGroupWelcome(wire []byte) ([]byte, error) {
	if len(wire) < 18 {
		return nil, fmt.Errorf("schat: an envelope needs a 16-byte token, a type and a payload; "+
			"this one is %d bytes", len(wire))
	}
	if wire[16] != ContentTypeGroupWelcome {
		return nil, fmt.Errorf("schat: envelope content type %#02x is not a group welcome", wire[16])
	}
	return wire[17:], nil
}
