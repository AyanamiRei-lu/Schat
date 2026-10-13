package mobile

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Where a joining member actually IS.
//
// Every binding test passes a leaf index by hand — `1` for the member who joined second, `3` for
// the third — and none of them ever checked that the tree agrees. The joining member uses that
// number to decide which private key to decrypt a path secret with, so a wrong number would let
// it decrypt a secret that was not addressed to it, rebuild a tree that is not the group's, and
// fail at the confirmation tag rather than at the decryption.
//
// That is exactly the shape of the failure being chased, and this is the only premise in the
// chain that has never been measured.

func TestTheJoiningMemberIsWhereTheCallerSaysItIs(t *testing.T) {
	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)

	// Bob's identity key, which is what his leaf carries.
	var bob struct {
		SigningPublic string `json:"signing_public"`
	}
	if err := json.Unmarshal([]byte(bobIdentity), &bob); err != nil {
		t.Fatalf("the identity JSON is not what this test expects: %v", err)
	}
	bobSigning, err := hex.DecodeString(bob.SigningPublic)
	if err != nil {
		t.Fatal(err)
	}

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

	// Join, claiming leaf 1 — which is what every other test claims.
	bobState, err := GroupProcessWelcome(added.WelcomeHex, bobKeyPackage.InitKeyPrivateHex,
		bobKeyPackage.LeafKeyPrivateHex)
	if err != nil {
		t.Fatal(err)
	}

	// Where does the tree say he is?
	var raw struct {
		Tree string `json:"tree"`
	}
	if err := json.Unmarshal([]byte(bobState), &raw); err != nil {
		t.Fatal(err)
	}
	treeBytes, err := hex.DecodeString(raw.Tree)
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := tree.ParseTree(mlstls.NewReader(treeBytes))
	if err != nil {
		t.Fatal(err)
	}

	actual := int64(-1)
	for node := 0; node < len(ratchet); node += 2 {
		holder := ratchet[node]
		if holder == nil || holder.Leaf == nil {
			continue
		}
		if string(holder.Leaf.SignatureKey) == string(bobSigning) {
			actual = int64(node / 2)
		}
	}

	t.Logf("the caller claimed leaf 1; the tree places Bob at leaf %d", actual)
	t.Logf("the tree has %d leaves", (len(ratchet)+1)/2)

	if actual < 0 {
		t.Fatal("Bob's identity key is in no leaf of the tree it just joined")
	}
	if actual != 1 {
		t.Fatalf("Bob joined claiming leaf 1, and the tree puts him at leaf %d. Every binding "+
			"test passes that index by hand, and a wrong one makes the member decrypt a path "+
			"secret addressed to somebody else", actual)
	}
}
