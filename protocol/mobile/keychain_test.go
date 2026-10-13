package mobile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Which of the two halves is wrong.
//
// The joining member holds a private key that does not correspond to the public key at his leaf
// in the tree. Two functions could be responsible, and they call for opposite fixes:
//
//   - GroupAddMember put a leaf in the tree that is not the one the KeyPackage describes;
//   - GroupProcessWelcome stored the wrong private key (the init key instead of the leaf key).
//
// Comparing the tree's leaf against the KeyPackage settles it in one run. The helper below is
// self-contained rather than a change to the existing one, because widening a shared helper's
// return would ripple through every caller — the mistake that broke a test file two rounds of
// work ago.

func aliceBobAndBobKeyPackage(t *testing.T) (aliceState, bobState string, keyPackage *messages.KeyPackage, bobKeyPackageHex string) {
	t.Helper()

	aliceIdentity := testIdentityJSON(t)
	bobIdentity := testIdentityJSON(t)

	created, err := GroupCreate(aliceIdentity, "67727031")
	if err != nil {
		t.Fatal(err)
	}

	generated, err := GroupKeyPackage(bobIdentity)
	if err != nil {
		t.Fatal(err)
	}
	bobKeyPackageHex = generated.KeyPackageHex

	raw, err := hex.DecodeString(generated.KeyPackageHex)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err = messages.ParseKeyPackage(mlstls.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	added, err := GroupAddMember(created, aliceIdentity, generated.KeyPackageHex)
	if err != nil {
		t.Fatal(err)
	}
	bobState, err = GroupProcessWelcome(added.WelcomeHex, generated.InitKeyPrivateHex,
		generated.LeafKeyPrivateHex)
	if err != nil {
		t.Fatal(err)
	}
	return added.StateJSON, bobState, keyPackage, generated.KeyPackageHex
}

func TestWhichHalfOfTheLeafKeyIsWrong(t *testing.T) {
	aliceState, bobState, keyPackage, keyPackageHex := aliceBobAndBobKeyPackage(t)

	suite := crypto.CipherSuite(GroupCipherSuite)

	readTree := func(state string) tree.Tree {
		t.Helper()
		var raw struct {
			Tree string `json:"tree"`
		}
		if err := json.Unmarshal([]byte(state), &raw); err != nil {
			t.Fatal(err)
		}
		treeBytes, err := hex.DecodeString(raw.Tree)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := tree.ParseTree(mlstls.NewReader(treeBytes))
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}

	aliceTree := readTree(aliceState)
	bobTree := readTree(bobState)

	if len(aliceTree) != len(bobTree) {
		t.Fatalf("the two trees have different sizes: %d against %d", len(aliceTree), len(bobTree))
	}

	// Find where the KeyPackage's leaf actually is in each tree.
	fromKeyPackage := keyPackage.LeafNode.EncryptionKey
	aliceIndex, bobIndex := -1, -1
	for node := 0; node < len(aliceTree); node += 2 {
		if aliceTree[node] != nil && aliceTree[node].Leaf != nil &&
			bytes.Equal(aliceTree[node].Leaf.EncryptionKey, fromKeyPackage) {
			aliceIndex = node / 2
		}
		if bobTree[node] != nil && bobTree[node].Leaf != nil &&
			bytes.Equal(bobTree[node].Leaf.EncryptionKey, fromKeyPackage) {
			bobIndex = node / 2
		}
	}

	t.Logf("the KeyPackage's leaf key = %x", fromKeyPackage)
	t.Logf("it is at leaf %d in the committer's tree, leaf %d in the joiner's tree",
		aliceIndex, bobIndex)
	t.Logf("node 2 in the committer's tree holds %x", leafKeyAt(aliceTree, 2))
	t.Logf("node 2 in the joiner's tree holds     %x", leafKeyAt(bobTree, 2))
	_ = keyPackageHex
	_ = suite

	// The two members must agree about where the new leaf is, or they are not in the same group.
	if aliceIndex != bobIndex {
		t.Fatalf("the two trees place this KeyPackage's leaf at different places: %d against %d",
			aliceIndex, bobIndex)
	}
	if aliceIndex < 0 {
		t.Fatal("neither tree contains the leaf this KeyPackage describes, so the commit did not " +
			"add the member the KeyPackage was made for")
	}
}

func leafKeyAt(t tree.Tree, node int) []byte {
	if node >= len(t) || t[node] == nil || t[node].Leaf == nil {
		return nil
	}
	return t[node].Leaf.EncryptionKey
}
