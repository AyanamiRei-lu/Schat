package mobile

import (
	"testing"
)

// The binding's whole reason to exist: one member creates a group, adds a second, and the
// second joins through the Welcome — entirely across the surface Kotlin can call.
//
// # Why this test matters more than the ones below it
//
// Every piece it exercises was verified separately: the commit machinery against its own
// end-to-end tests, the Welcome against a three-member test inside the group package, the
// key schedule against the official vectors. What none of those could check is whether the
// BINDING passes everything that has to be passed — and three separate defects lived exactly
// there: a discarded init key, a GroupInfo with no ratchet tree, and an AcceptWelcome that
// demanded a tree its only caller could not have.
//
// Those defects were invisible to every test that existed, because each of them was a piece of
// information that had to be carried from one call to the next, and no test had ever made the
// journey. This one does.

func TestBindingEndToEndCreateAddAndJoin(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)

	// Alice creates a group. A group of one is a single node, which is why her first commit
	// cannot carry an update path and must be an Add.
	aliceState, err := GroupCreate(aliceIdentity, "67727031") // "grp1"
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}

	before, err := GroupStateSummary(aliceState)
	if err != nil {
		t.Fatal(err)
	}
	if before.MemberCount != 1 || before.Epoch != 0 {
		t.Fatalf("the new group has %d members at epoch %d", before.MemberCount, before.Epoch)
	}

	// Bob produces a KeyPackage to publish, and keeps the init private key that comes with it.
	bobKeyPackage, err := GroupKeyPackage(bobIdentity)
	if err != nil {
		t.Fatalf("GroupKeyPackage: %v", err)
	}
	if bobKeyPackage.KeyPackageHex == "" || bobKeyPackage.InitKeyPrivateHex == "" {
		t.Fatal("the KeyPackage result is missing a part: both the published package and the init " +
			"key are needed, and the init key is the one that cannot be recovered later")
	}

	// Alice adds him.
	added, err := GroupAddMember(aliceState, aliceIdentity, bobKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("GroupAddMember: %v", err)
	}
	if added.CommitHex == "" {
		t.Fatal("no commit was produced, so the members already in the group would never learn " +
			"about the addition")
	}
	if added.WelcomeHex == "" {
		t.Fatal("no Welcome was produced, so the member being added could never join")
	}

	afterAdd, err := GroupStateSummary(added.StateJSON)
	if err != nil {
		t.Fatalf("the committer's new state does not restore: %v", err)
	}
	if afterAdd.MemberCount != 2 {
		t.Fatalf("after adding, the group has %d members, want 2", afterAdd.MemberCount)
	}
	if afterAdd.Epoch != 1 {
		t.Fatalf("after one commit the epoch is %d, want 1", afterAdd.Epoch)
	}

	// Bob joins, with nothing but the Welcome and the init key he kept.
	bobState, err := GroupProcessWelcome(added.WelcomeHex, bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex)
	if err != nil {
		t.Fatalf("Bob could not join: %v", err)
	}

	afterJoin, err := GroupStateSummary(bobState)
	if err != nil {
		t.Fatalf("the joiner's state does not restore: %v", err)
	}

	// The assertions that say they are in the SAME group rather than merely in a group.
	if afterJoin.GroupIDHex != afterAdd.GroupIDHex {
		t.Fatalf("the two members disagree about the group: %q against %q",
			afterJoin.GroupIDHex, afterAdd.GroupIDHex)
	}
	if afterJoin.Epoch != afterAdd.Epoch {
		t.Fatalf("Bob joined epoch %d while Alice is in %d", afterJoin.Epoch, afterAdd.Epoch)
	}
	if afterJoin.MemberCount != afterAdd.MemberCount {
		t.Fatalf("the two members disagree about who is in the group: %d against %d",
			afterJoin.MemberCount, afterAdd.MemberCount)
	}
	if afterJoin.EpochAuthenticatorHex != afterAdd.EpochAuthenticatorHex {
		t.Fatal("the two members derived different epoch authenticators, so they are in the same " +
			"group only by name — every message either sends would be unreadable to the other")
	}
	if afterJoin.CipherSuite != GroupCipherSuite {
		t.Fatalf("Bob joined with suite %#04x", afterJoin.CipherSuite)
	}

	t.Logf("Alice and Bob agree on epoch %d of a %d-member group (%s…)",
		afterJoin.Epoch, afterJoin.MemberCount, afterJoin.EpochAuthenticatorHex[:16])
}

func TestJoiningRefusesTheWrongInitKey(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)
	carolIdentity := testIdentityJSON(t)

	aliceState, err := GroupCreate(aliceIdentity, "67727032")
	if err != nil {
		t.Fatal(err)
	}
	bobKeyPackage, err := GroupKeyPackage(bobIdentity)
	if err != nil {
		t.Fatal(err)
	}
	carolKeyPackage, err := GroupKeyPackage(carolIdentity)
	if err != nil {
		t.Fatal(err)
	}

	added, err := GroupAddMember(aliceState, aliceIdentity, bobKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatal(err)
	}

	// Carol's init key must not open Bob's entry: the Welcome is addressed to one member, and
	// HPKE authentication is what enforces it.
	if _, err := GroupProcessWelcome(added.WelcomeHex, carolKeyPackage.InitKeyPrivateHex, carolKeyPackage.LeafKeyPrivateHex); err == nil {
		t.Fatal("a Welcome addressed to one member opened with another member's init key")
	}

	// The right key still works, so the test above is not passing on a broken Welcome.
	if _, err := GroupProcessWelcome(added.WelcomeHex, bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex); err != nil {
		t.Fatalf("the intended member could not join: %v", err)
	}

	if _, err := GroupProcessWelcome("not hex", bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex); err == nil {
		t.Fatal("a non-hex Welcome was accepted")
	}
	if _, err := GroupProcessWelcome(added.WelcomeHex, "", ""); err == nil {
		t.Fatal("an empty init key was accepted")
	}
}
