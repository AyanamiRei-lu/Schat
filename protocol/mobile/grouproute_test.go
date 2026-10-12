package mobile

import (
	"testing"
)

// The group's route key: the value every member must derive identically, and which must change
// when the group does.

func TestGroupRouteKeyIsTheSameForEveryMember(t *testing.T) {
	aliceIdentity, _, aliceState, bobState := membersInAGroup(t)

	aliceKey, err := GroupRouteKey(aliceState)
	if err != nil {
		t.Fatalf("Alice's route key: %v", err)
	}
	bobKey, err := GroupRouteKey(bobState)
	if err != nil {
		t.Fatalf("Bob's route key: %v", err)
	}

	// This is the property the whole scheme rests on. Nothing distributed this key to Bob: he
	// derived it from the epoch he joined, which is why the Welcome did not have to carry it —
	// and why a member cannot be handed a key for an epoch it is not in.
	if aliceKey != bobKey {
		t.Fatal("two members of the same epoch derived different route keys, so neither could " +
			"address the other and neither would notice until messages stopped arriving")
	}
	if len(aliceKey) != 64 {
		t.Fatalf("the route key is %d hex characters, want 64 (32 bytes)", len(aliceKey))
	}
	if aliceIdentity == "" {
		t.Fatal("the fixture returned no identity")
	}
}

func TestGroupRouteKeyChangesWithTheEpoch(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)

	created, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatal(err)
	}
	atEpochZero, err := GroupRouteKey(created)
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
	atEpochOne, err := GroupRouteKey(added.StateJSON)
	if err != nil {
		t.Fatal(err)
	}

	// The commit moved the group to a new epoch, so the route changed. THIS is what makes a
	// removal effective: a member who is not in the new epoch cannot derive its route key, and
	// so cannot follow the conversation to where it moved.
	if atEpochZero == atEpochOne {
		t.Fatal("the route key did not change when the epoch did, so a member who was removed " +
			"would keep receiving everything said after they left")
	}

	// And Bob, who joined at the new epoch, agrees with Alice there.
	bobState, err := GroupProcessWelcome(added.WelcomeHex, bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex)
	if err != nil {
		t.Fatal(err)
	}
	bobAtEpochOne, err := GroupRouteKey(bobState)
	if err != nil {
		t.Fatal(err)
	}
	if bobAtEpochOne != atEpochOne {
		t.Fatal("the member who joined by Welcome disagrees with the committer about the route key")
	}
}

func TestGroupRouteKeyIsNotSharedBetweenGroups(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)

	first, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatal(err)
	}
	second, err := GroupCreate(aliceIdentity, "67727032")
	if err != nil {
		t.Fatal(err)
	}

	firstKey, err := GroupRouteKey(first)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := GroupRouteKey(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstKey == secondKey {
		t.Fatal("two different groups derived the same route key, so their messages would be " +
			"delivered to the same mailbox")
	}

	if _, err := GroupRouteKey("not json"); err == nil {
		t.Fatal("a route key was derived from something that is not a group state")
	}
}
