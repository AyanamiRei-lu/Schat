package mobile

import (
	"bytes"
	"testing"
)

// The commit envelope, and the one leaf index a client cannot guess.
//
// These two go together because they are used together: a client receives a commit, reads the
// leaf it belongs to from its own state, and applies the commit as that leaf. Getting the type
// wrong sends the commit down the message path; getting the leaf wrong makes the member decrypt
// a path secret addressed to somebody else. The first fails loudly, the second fails at the
// confirmation tag — which is why the leaf index is asserted here rather than assumed.

func TestGroupCommitEnvelopeRoundTrip(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	commit := []byte("an MLS commit")

	wire, err := WrapGroupCommit(token, commit)
	if err != nil {
		t.Fatalf("WrapGroupCommit: %v", err)
	}
	if wire[16] != ContentTypeGroupCommit {
		t.Fatalf("the content type is %#02x, want %#02x", wire[16], ContentTypeGroupCommit)
	}
	if !bytes.Equal(wire[:16], mustHexBytes(t, token)) {
		t.Fatal("the token did not survive, so the commit would go to the wrong mailbox")
	}

	payload, err := UnwrapGroupCommit(wire)
	if err != nil {
		t.Fatalf("UnwrapGroupCommit: %v", err)
	}
	if !bytes.Equal(payload, commit) {
		t.Fatalf("the commit came back as %q", payload)
	}
}

func TestTheFourGroupTypesAreNotInterchangeable(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"
	payload := []byte("payload")

	make := func(kind byte) []byte {
		wire := append(mustHexBytes(t, token), kind)
		return append(wire, payload...)
	}

	// A message (0x03) is neither a welcome nor a commit.
	if _, err := UnwrapGroupWelcome(make(ContentTypeGroup)); err == nil {
		t.Fatal("a group message was accepted as a welcome")
	}
	if _, err := UnwrapGroupCommit(make(ContentTypeGroup)); err == nil {
		t.Fatal("a group message was accepted as a commit")
	}

	// A welcome (0x04) must NOT be readable as a commit: the two are applied by completely
	// different code, and a client that applied a welcome as a commit would try to move an epoch
	// it is not in.
	if _, err := UnwrapGroupCommit(make(ContentTypeGroupWelcome)); err == nil {
		t.Fatal("a welcome was accepted as a commit, so a client would try to apply a group " +
			"change for an epoch it does not hold")
	}
	// And a commit must not be readable as a welcome.
	if _, err := UnwrapGroupWelcome(make(ContentTypeGroupCommit)); err == nil {
		t.Fatal("a commit was accepted as a welcome, so a client would try to join a group it is " +
			"already in")
	}

	// The one-to-one types stay refused by all three.
	for _, kind := range []byte{0x01, 0x02} {
		if _, err := UnwrapGroupCommit(make(kind)); err == nil {
			t.Fatalf("content type %#02x was accepted as a commit", kind)
		}
	}
}

func TestGroupCommitEnvelopeRejectsBadInput(t *testing.T) {
	token := "00112233445566778899aabbccddeeff"

	if _, err := WrapGroupCommit("zz", []byte("commit")); err == nil {
		t.Fatal("a non-hex token was accepted")
	}
	if _, err := WrapGroupCommit(token, nil); err == nil {
		t.Fatal("an empty commit was accepted")
	}
	if _, err := UnwrapGroupCommit(append(mustHexBytes(t, token), ContentTypeGroupCommit)); err == nil {
		t.Fatal("an envelope with a type and no payload was accepted")
	}
	if _, err := UnwrapGroupCommit([]byte("short")); err == nil {
		t.Fatal("a truncated envelope was accepted")
	}
}

func TestTheMemberKnowsWhichLeafItIs(t *testing.T) {
	// Bob joins a group Alice created. He is the second member, and in a two-leaf tree that is
	// leaf 1 — but the point is that the FUNCTION agrees, not that this test knows.
	// The state is Bob's; his identity is the one that joined it. Rebuild the pair properly.
	aliceIdentity := testIdentityJSON(t)
	created, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatal(err)
	}
	kp, err := GroupKeyPackage(testIdentityJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	added, err := GroupAddMember(created, aliceIdentity, kp.KeyPackageHex)
	if err != nil {
		t.Fatal(err)
	}
	bobState, err := GroupProcessWelcome(added.WelcomeHex, kp.InitKeyPrivateHex,
		kp.LeafKeyPrivateHex)
	if err != nil {
		t.Fatal(err)
	}

	// Alice is leaf 0 in the same group.
	aliceLeaf, err := GroupMyLeaf(added.StateJSON, aliceIdentity)
	if err != nil {
		t.Fatalf("GroupMyLeaf for the creator: %v", err)
	}
	if aliceLeaf != 0 {
		t.Fatalf("the creator is at leaf %d, want 0", aliceLeaf)
	}

	// The tree is shared: Alice is at leaf 0 in Bob's copy of it too. That is not a triviality —
	// a member's index must be the same for everybody, or two members would address the same
	// person differently.
	aliceInBobsTree, err := GroupMyLeaf(bobState, aliceIdentity)
	if err != nil {
		t.Fatalf("GroupMyLeaf for Alice in Bob's copy of the tree: %v", err)
	}
	if aliceInBobsTree != 0 {
		t.Fatalf("Alice is at leaf %d in Bob's tree and 0 in her own", aliceInBobsTree)
	}

	// An identity that occupies no leaf must be refused. The first version of this test used
	// Alice for that, which was wrong for the obvious reason a test can be wrong: she is in the
	// group.
	outsider := testIdentityJSON(t)
	if _, err := GroupMyLeaf(bobState, outsider); err == nil {
		t.Fatal("an identity that occupies no leaf of the group was reported as a member, so the " +
			"function is not checking the tree")
	}
	if _, err := GroupMyLeaf("not a state", aliceIdentity); err == nil {
		t.Fatal("a leaf was reported for something that is not a group state")
	}
}
