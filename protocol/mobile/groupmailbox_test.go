package mobile

import (
	"strings"
	"testing"
)

// A group's mailboxes.
//
// The property that matters is the one nothing distributes: two members of the same epoch derive
// the same tokens without either being told. If that fails, messages are sent to a mailbox
// nobody is listening on, and the send SUCCEEDS — which is why it has to be asserted rather than
// assumed.

func TestGroupMailboxTokensAgreeBetweenMembers(t *testing.T) {
	_, _, aliceState, bobState := membersInAGroup(t)

	// A fixed token epoch, because the value depends on the wall clock: two members asking at
	// different moments are expected to differ near a boundary, and that is what the token count
	// is for.
	const tokenEpoch = 12345

	alice, err := GroupMailboxTokens(aliceState, tokenEpoch, 3)
	if err != nil {
		t.Fatalf("Alice: %v", err)
	}
	bob, err := GroupMailboxTokens(bobState, tokenEpoch, 3)
	if err != nil {
		t.Fatalf("Bob: %v", err)
	}

	if alice != bob {
		t.Fatalf("two members of the same epoch derived different mailboxes:\n  Alice: %s\n  Bob:   %s",
			alice, bob)
	}

	tokens := strings.Split(alice, ",")
	if len(tokens) != 3 {
		t.Fatalf("asked for 3 mailboxes and got %d", len(tokens))
	}
	seen := map[string]bool{}
	for _, token := range tokens {
		if len(token) != 32 {
			t.Fatalf("a mailbox token is %d characters, want 32: %q", len(token), token)
		}
		if strings.Contains(token, ",") {
			t.Fatal("a token contains a comma, which would make the comma-separated list ambiguous")
		}
		if seen[token] {
			t.Fatal("the same mailbox appears twice, so a receiver subscribing to all of them " +
				"would subscribe twice and a sender would have one fewer neighbour to reach")
		}
		seen[token] = true
	}
}

func TestGroupMailboxTokensDifferAcrossEpochs(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)

	created, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatal(err)
	}
	bobKeyPackage, err := GroupKeyPackage(bobIdentity)
	if err != nil {
		t.Fatal(err)
	}
	added, err := GroupAddMember(created, aliceIdentity, bobKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatal(err)
	}

	const tokenEpoch = 12345
	before, err := GroupMailboxTokens(created, tokenEpoch, 1)
	if err != nil {
		t.Fatal(err)
	}
	after, err := GroupMailboxTokens(added.StateJSON, tokenEpoch, 1)
	if err != nil {
		t.Fatal(err)
	}

	// The commit moved the group to a new epoch, so its mailboxes moved too. A member who was
	// removed cannot derive the new ones — which is how a removal takes effect.
	if before == after {
		t.Fatal("the group's mailboxes did not change when its epoch did")
	}

	// And the token epoch itself must matter: that is what gives a receiver tolerance for a
	// clock that has drifted across a boundary.
	later, err := GroupMailboxTokens(added.StateJSON, tokenEpoch+1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if later == after {
		t.Fatal("the token epoch had no effect, so a receiver would have no tolerance for a " +
			"clock that drifted across a boundary")
	}
}

func TestGroupMailboxTokensRejectsBadInput(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	state, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := GroupMailboxTokens(state, 12345, 0); err == nil {
		t.Fatal("a group with no mailboxes was accepted")
	}
	if _, err := GroupMailboxTokens(state, 12345, -1); err == nil {
		t.Fatal("a negative token count was accepted")
	}
	// Each token is a subscription the relay has to hold, so an unbounded count is a way to make
	// the relay hold an unbounded number of them for one group.
	if _, err := GroupMailboxTokens(state, 12345, 1000); err == nil {
		t.Fatal("an unbounded token count was accepted")
	}
	if _, err := GroupMailboxTokens("not a state", 12345, 1); err == nil {
		t.Fatal("mailboxes were derived from something that is not a group state")
	}
}
