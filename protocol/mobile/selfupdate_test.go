package mobile

import (
	"testing"
)

// A member that has REPLACED ITS OWN LEAF can still follow somebody else's commit.
//
// Three commits are needed to reach the thing under test, and each one is load-bearing:
//
//	1. Alice adds Bob          — Bob joins and holds a leaf key
//	2. BOB adds Carol          — Bob's own leaf is REPLACED, so his usable key becomes a new one
//	3. Alice adds a fourth     — Bob must follow it, using the key step 2 gave him
//
// A two-step version of this test (Alice commits, Bob follows) passes without ever touching
// step 2, and therefore proves nothing about the key that step 2 produces. That is the whole
// reason for the third commit: the key being tested only comes into existence when a member
// updates itself.
//
// Without it a member holds the key it joined with, its leaf publishes a different one, and the
// failure surfaces as an inability to decrypt a path secret addressed to it — which reads as a
// cryptographic fault and is a bookkeeping one.

func TestAMemberThatUpdatedItsOwnLeafCanStillFollow(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)
	carolIdentity := testIdentityJSON(t)

	// --- 1. Alice creates the group and adds Bob ------------------------------------------
	aliceState, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}

	bobKeyPackage, err := GroupKeyPackage(bobIdentity)
	if err != nil {
		t.Fatal(err)
	}
	aliceAddedBob, err := GroupAddMember(aliceState, aliceIdentity, bobKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("adding Bob: %v", err)
	}
	aliceState = aliceAddedBob.StateJSON

	bobState, err := GroupProcessWelcome(aliceAddedBob.WelcomeHex,
		bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex)
	if err != nil {
		t.Fatalf("Bob could not join: %v", err)
	}

	// --- 2. BOB commits: he adds Carol, which REPLACES HIS OWN LEAF ------------------------
	carolKeyPackage, err := GroupKeyPackage(carolIdentity)
	if err != nil {
		t.Fatal(err)
	}
	bobAddedCarol, err := GroupAddMember(bobState, bobIdentity, carolKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("Bob could not add Carol: %v", err)
	}
	bobState = bobAddedCarol.StateJSON

	// Alice, the existing member, applies Bob's commit. She is leaf 0.
	aliceState, err = GroupProcessCommit(aliceState, bobAddedCarol.CommitHex, 0)
	if err != nil {
		t.Fatalf("Alice could not apply Bob's commit: %v", err)
	}

	aliceSummary, err := GroupStateSummary(aliceState)
	if err != nil {
		t.Fatal(err)
	}
	bobSummary, err := GroupStateSummary(bobState)
	if err != nil {
		t.Fatal(err)
	}
	if aliceSummary.EpochAuthenticatorHex != bobSummary.EpochAuthenticatorHex {
		t.Fatal("Alice and Bob disagree after Bob's own commit, so the test would fail later for " +
			"a reason unrelated to what it is testing")
	}
	t.Logf("after Bob's commit both are at epoch %d", aliceSummary.Epoch)

	// --- 3. Alice commits again; Bob must follow with HIS NEW KEY -------------------------
	fourthIdentity := testIdentityJSON(t)
	fourthKeyPackage, err := GroupKeyPackage(fourthIdentity)
	if err != nil {
		t.Fatal(err)
	}
	aliceAddedFourth, err := GroupAddMember(aliceState, aliceIdentity, fourthKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("Alice could not add a fourth member: %v", err)
	}

	// THE ASSERTION THIS TEST EXISTS FOR. Bob is leaf 1, and the key he must use was produced by
	// his own commit in step 2 — not the one he joined with.
	bobAfter, err := GroupProcessCommit(bobState, aliceAddedFourth.CommitHex, 1)
	if err != nil {
		t.Fatalf("Bob could not follow a commit made after he replaced his own leaf, so he is "+
			"holding a key his leaf no longer publishes: %v", err)
	}

	aliceFinal, err := GroupStateSummary(aliceAddedFourth.StateJSON)
	if err != nil {
		t.Fatal(err)
	}
	bobFinal, err := GroupStateSummary(bobAfter)
	if err != nil {
		t.Fatal(err)
	}

	if bobFinal.Epoch != aliceFinal.Epoch {
		t.Fatalf("Bob is at epoch %d and Alice at %d", bobFinal.Epoch, aliceFinal.Epoch)
	}
	if bobFinal.EpochAuthenticatorHex != aliceFinal.EpochAuthenticatorHex {
		t.Fatal("Bob followed the commit but reached a different epoch than Alice")
	}
	if bobFinal.MemberCount != aliceFinal.MemberCount {
		t.Fatalf("Bob sees %d members and Alice %d", bobFinal.MemberCount, aliceFinal.MemberCount)
	}

	t.Logf("Bob replaced his own leaf, then followed another member's commit to epoch %d with "+
		"%d members", bobFinal.Epoch, bobFinal.MemberCount)
}
