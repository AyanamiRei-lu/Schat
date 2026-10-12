package mobile

import (
	"encoding/hex"
	"fmt"

	"github.com/schat/schat/protocol/mls/group"
	"github.com/schat/schat/protocol/mls/schedule"
)

// The route key a group's messages are delivered under.
//
// # Why a group needs one derived rather than generated
//
// A one-to-one session generates a fresh route key and hands it to the peer as part of the
// connection information. A group cannot: every member has to arrive at the SAME key without
// anybody sending it, and it has to change when the group changes, or a member who was removed
// keeps receiving what is said after they left.
//
// MLS provides exactly this mechanism, and it is the exporter:
//
//	route_key = Export(epoch_secrets, "schat group route", group_id, 32)
//
// It is not a construction invented here. The exporter exists so that an application can derive
// its own values from an epoch, and it has the two properties a group route needs for free:
//
//   - every member of the epoch derives the same value, because every member holds the same
//     exporter secret — nothing has to be distributed;
//   - the value changes when the epoch does, and the epoch changes on every commit. A member who
//     was removed is not in the new epoch and cannot derive its route key, so the removal takes
//     effect on the very next message rather than whenever somebody remembers to rotate.
//
// # What the relay learns
//
// The relay sees one delivery token per message, the same as it does for a one-to-one message.
// It does not learn the group's size, which members are talking, or that the message is a group
// message at all — the envelope's content type is the only thing that says so, and the relay
// does not read it.

// GroupRouteKey returns the hex route key for the group state's current epoch.
//
// The caller feeds it to DeliveryTokens to get the mailboxes to subscribe to and to send to.
// Two members of the same group in the same epoch get the same key; a member in a different
// epoch gets a different one, which is what makes a removal take effect.
func GroupRouteKey(stateJSON string) (string, error) {
	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return "", err
	}
	if len(epoch.Context.GroupID) == 0 {
		return "", fmt.Errorf("schat: the group state names no group")
	}

	key, err := schedule.Export(epoch.Secrets, "schat group route", epoch.Context.GroupID, 32, epoch.Suite)
	if err != nil {
		return "", fmt.Errorf("schat: deriving the group route key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
