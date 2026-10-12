package mobile

import (
	"testing"
)

// A member following a commit, through the binding.
//
// The group package proves the mechanism; this proves the SURFACE. It is the exact sequence the
// application performs: Bob joins through a Welcome, Alice adds somebody else, and Bob applies
// the commit that reaches him. Everything in between — which key Bob uses, where it comes from,
// which leaf he claims — has to be carried by the binding, and none of it is visible to a test
// that only exercises the group package.

func TestFollowingACommitThroughTheBinding(t *testing.T) {
	// ONE fixture, for both members. An earlier version of this test took Alice from one and Bob
	// from another, and the commit was then verified against a tree holding a different identity —
	// which fails as a signature error and says nothing about the code under test.
	aliceIdentity, _, aliceAfterJoin, bobState := aliceAndState(t)

	// Alice adds a third member; Bob is not the one being added, so this commit reaches him.
	carolIdentity := testIdentityJSON(t)
	carolKeyPackage, err := GroupKeyPackage(carolIdentity)
	if err != nil {
		t.Fatal(err)
	}
	added, err := GroupAddMember(aliceAfterJoin, aliceIdentity, carolKeyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("GroupAddMember: %v", err)
	}
	if added.CommitHex == "" {
		t.Fatal("no commit was produced, so there is nothing for the existing members to apply")
	}

	aliceSummary, err := GroupStateSummary(added.StateJSON)
	if err != nil {
		t.Fatal(err)
	}
	before, err := GroupStateSummary(bobState)
	if err != nil {
		t.Fatal(err)
	}
	if before.Epoch == aliceSummary.Epoch {
		t.Fatal("Bob is already in the epoch the commit opens, so this test would prove nothing")
	}

	// Bob applies it. He is leaf 1, and the binding must reach the key he derived when he joined.
	bobAfter, err := GroupProcessCommit(bobState, added.CommitHex, 1)
	if err != nil {
		t.Fatalf("Bob could not apply the commit: %v", err)
	}

	bobSummary, err := GroupStateSummary(bobAfter)
	if err != nil {
		t.Fatalf("Bob's new state does not restore: %v", err)
	}

	if bobSummary.Epoch != aliceSummary.Epoch {
		t.Fatalf("Bob is at epoch %d and Alice at %d", bobSummary.Epoch, aliceSummary.Epoch)
	}
	if bobSummary.EpochAuthenticatorHex != aliceSummary.EpochAuthenticatorHex {
		t.Fatal("Bob reached a different epoch than Alice, so the two are in the same group only " +
			"by name")
	}
	if bobSummary.MemberCount != 3 {
		t.Fatalf("Bob sees %d members and Alice %d", bobSummary.MemberCount, aliceSummary.MemberCount)
	}

	// The shared state must survive being stored and loaded, or the member is only up to date
	// until the app restarts.
	reloaded, err := GroupStateSummary(bobAfter)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.EpochAuthenticatorHex != aliceSummary.EpochAuthenticatorHex {
		t.Fatal("the state Bob ended up with does not restore to the same epoch")
	}

}

// aliceAndState returns Alice's identity and the state she holds after adding Bob — which is the
// state a second Add must start from.
func aliceAndState(t *testing.T) (string, string, string, string) {
	t.Helper()

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
	bobState, err := GroupProcessWelcome(added.WelcomeHex, bobKeyPackage.InitKeyPrivateHex, bobKeyPackage.LeafKeyPrivateHex)
	if err != nil {
		t.Fatal(err)
	}
	return aliceIdentity, bobIdentity, added.StateJSON, bobState
}
