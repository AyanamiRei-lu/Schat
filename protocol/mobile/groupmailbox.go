package mobile

import (
	"fmt"
	"strings"
)

// The mailboxes a group's messages go to.
//
// # Why this returns a string and not a list
//
// The Kotlin side has to take a list of tokens and use every one of them — subscribe to all, and
// send to one. gomobile turns a Go []string into a generated type whose exact shape is a detail
// of the binding, and a client that guessed wrong would fail to compile for a reason that says
// nothing about the problem.
//
// Returning a comma-separated string moves that uncertainty to the side that can be TESTED. A
// token is 32 hex characters and can never contain a comma, so the split is unambiguous — and
// the rule that makes it so lives here, beside the code that guarantees it, rather than in a
// client that has to know it.
//
// # The tokens come from the epoch, so they move with it
//
// GroupRouteKey derives one value per epoch from the exporter, and the tokens are derived from
// that value. A member who is not in the epoch cannot derive either, which is what makes a
// removal take effect on the next message rather than whenever somebody remembers to rotate.

// GroupMailboxTokens returns the mailboxes this epoch's group messages use, comma-separated.
//
// count is how many tokens to derive. More than one gives tolerance for a clock that has drifted
// across an epoch boundary: a receiver subscribes to all of them, so a message sent under a
// neighbouring epoch is still delivered.
func GroupMailboxTokens(stateJSON string, tokenEpoch int64, count int64) (string, error) {
	if count <= 0 {
		return "", fmt.Errorf("schat: a group needs at least one mailbox token")
	}
	if count > 64 {
		// Each token is a subscription the relay has to keep. A caller asking for thousands is
		// asking the relay to hold thousands of mailboxes for one group.
		return "", fmt.Errorf("schat: %d tokens is more than a group should need", count)
	}

	routeKey, err := GroupRouteKey(stateJSON)
	if err != nil {
		return "", err
	}

	// The token epoch comes from the caller: it is derived from the WALL CLOCK, not from the
	// group's epoch number, because its purpose is to tolerate a clock that has drifted across
	// a boundary. Passing it in keeps this function free of a clock of its own — which would be
	// a second source of "now" and therefore a second answer.
	tokens, err := DeliveryTokens(routeKey, tokenEpoch, int(count))
	if err != nil {
		return "", fmt.Errorf("schat: deriving the group's mailboxes: %w", err)
	}
	if len(tokens) == 0 {
		return "", fmt.Errorf("schat: the group route key produced no mailboxes")
	}

	for _, token := range tokens {
		if strings.Contains(token, ",") {
			return "", fmt.Errorf("schat: a delivery token contains a comma, which would make the " +
				"list ambiguous; the tokens must stay hex")
		}
	}
	return strings.Join(tokens, ","), nil
}
