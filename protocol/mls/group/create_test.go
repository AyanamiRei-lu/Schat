package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/schedule"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Creating a group, and the one thing that cannot be checked about it yet.
//
// # Why there is no commit in this test
//
// A one-member group's tree has a single node, and that node is both the leaf and the root. A
// commit's update path is the chain of nodes ABOVE the sender's leaf, so for the only member
// that chain is empty and there is no path to generate. The creator therefore cannot make a
// self-update; its first commit has to be an Add, which places a second leaf and makes a path
// exist.
//
// Add needs a KeyPackage, which this project has not implemented, so the "a created group can
// immediately commit" check has to wait. What CAN be checked now is that the state creation
// produces is internally exact — that every derived value is the one the specification's steps
// produce — and that is what the assertions below do, recomputing each value from the
// primitives rather than from the code under test.

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func creatorLeaf(t *testing.T) (*tree.LeafNode, []byte, []byte) {
	t.Helper()

	priv, pub := signerFor("creator")
	_, leafPub := hpkeKeyFor(t, "creator-leaf")

	return &tree.LeafNode{
		EncryptionKey: leafPub,
		SignatureKey:  pub,
		Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("creator")},
		Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
		Source:        tree.LeafNodeSourceUpdate,
	}, priv, pub
}

func TestCreateGroupProducesAnExactInitialState(t *testing.T) {
	leaf, _, _ := creatorLeaf(t)
	groupID := randomBytes(t, suiteUnderTest.HashSize())
	epochSecret := randomBytes(t, suiteUnderTest.HashSize())

	created, err := CreateGroup(CreateGroupSpec{
		Suite:       suiteUnderTest,
		GroupID:     groupID,
		Creator:     leaf,
		EpochSecret: epochSecret,
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	epoch := created.Epoch

	// A tree with ONE node, which is both the leaf and the root.
	if len(epoch.Tree) != 1 {
		t.Fatalf("a one-member group's tree has %d nodes, want exactly 1", len(epoch.Tree))
	}
	if epoch.Tree[0] == nil || epoch.Tree[0].Leaf == nil {
		t.Fatal("the single node is not the creator's leaf")
	}
	root, err := tree.Root(1)
	if err != nil {
		t.Fatal(err)
	}
	if root != 0 {
		t.Fatalf("the root of a one-leaf tree is %d, want 0 — the leaf is the root", root)
	}

	if epoch.Number != 0 {
		t.Fatalf("a new group starts at epoch %d, want 0", epoch.Number)
	}
	if !bytes.Equal(epoch.Context.GroupID, groupID) {
		t.Fatal("the group ID did not survive")
	}
	if len(epoch.Context.ConfirmedTranscriptHash) != 0 {
		t.Fatalf("epoch 0's confirmed transcript hash is %d bytes; it must be the zero-length "+
			"octet string, not a hash of anything", len(epoch.Context.ConfirmedTranscriptHash))
	}

	// The epoch's secrets must be the ones derived from the epoch secret the caller supplied,
	// recomputed here from the primitive rather than from the field being checked.
	expected, err := schedule.SecretsFromEpochSecret(epochSecret, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2][]byte{
		"init secret":         {epoch.Secrets.InitSecret, expected.InitSecret},
		"encryption secret":   {epoch.Secrets.EncryptionSecret, expected.EncryptionSecret},
		"confirmation key":    {epoch.Secrets.ConfirmationKey, expected.ConfirmationKey},
		"membership key":      {epoch.Secrets.MembershipKey, expected.MembershipKey},
		"epoch authenticator": {epoch.Secrets.EpochAuthenticator, expected.EpochAuthenticator},
		"sender data secret":  {epoch.Secrets.SenderDataSecret, expected.SenderDataSecret},
		"exporter secret":     {epoch.Secrets.ExporterSecret, expected.ExporterSecret},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("the %s is not the one the epoch secret derives", name)
		}
	}

	// The confirmation tag is a MAC over the EMPTY confirmed transcript hash, and the interim
	// hash folds it in. Both are recomputed here.
	wantTag, err := messages.ConfirmationTag(expected.ConfirmationKey, []byte{}, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(created.ConfirmationTag, wantTag) {
		t.Fatal("the confirmation tag is not a MAC over the empty confirmed transcript hash")
	}

	interimInput, err := messages.InterimTranscriptHashInput(wantTag)
	if err != nil {
		t.Fatal(err)
	}
	wantInterim := suiteUnderTest.Hash(append([]byte{}, interimInput...))
	if !bytes.Equal(epoch.Transcript.Interim, wantInterim) {
		t.Fatal("the interim transcript hash is not Hash(confirmed || confirmation tag)")
	}
	if len(epoch.Transcript.Interim) == 0 {
		t.Fatal("the interim transcript hash is empty, so the next epoch's chain would start " +
			"from nothing")
	}

	// The tree hash in the context must be the hash of the tree that is actually there.
	wantTreeHash, err := treeHashOf(epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(epoch.Context.TreeHash, wantTreeHash) {
		t.Fatal("the group context's tree hash does not match the tree it describes")
	}

	// A created group has nobody to welcome, so the two secrets that belong to that path must
	// be empty rather than filled with something plausible.
	if len(epoch.Secrets.JoinerSecret) != 0 || len(epoch.Secrets.WelcomeSecret) != 0 {
		t.Fatal("creation populated the joiner or welcome secret, which it never derives")
	}
}

// TestCreateGroupIsDeterministicAndDependsOnItsSecret pins the two properties a group's start
// must have: the same inputs give the same state, and a different epoch secret gives different
// keys. Without the second, two groups could share every secret.
func TestCreateGroupIsDeterministicAndDependsOnItsSecret(t *testing.T) {
	leaf, _, _ := creatorLeaf(t)
	groupID := randomBytes(t, 16)

	secretA := randomBytes(t, suiteUnderTest.HashSize())
	secretB := randomBytes(t, suiteUnderTest.HashSize())

	first, err := CreateGroup(CreateGroupSpec{Suite: suiteUnderTest, GroupID: groupID, Creator: leaf, EpochSecret: secretA})
	if err != nil {
		t.Fatal(err)
	}
	again, err := CreateGroup(CreateGroupSpec{Suite: suiteUnderTest, GroupID: groupID, Creator: leaf, EpochSecret: secretA})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Epoch.Secrets.EncryptionSecret, again.Epoch.Secrets.EncryptionSecret) {
		t.Fatal("the same inputs produced different epoch keys")
	}
	if !bytes.Equal(first.ConfirmationTag, again.ConfirmationTag) {
		t.Fatal("the same inputs produced different confirmation tags")
	}

	other, err := CreateGroup(CreateGroupSpec{Suite: suiteUnderTest, GroupID: groupID, Creator: leaf, EpochSecret: secretB})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Epoch.Secrets.EncryptionSecret, other.Epoch.Secrets.EncryptionSecret) {
		t.Fatal("two different epoch secrets produced the same encryption secret, so the group's " +
			"keys do not depend on the randomness that is supposed to seed them")
	}
	if !bytes.Equal(first.Epoch.Context.TreeHash, other.Epoch.Context.TreeHash) {
		t.Fatal("the tree hash changed between two groups with the same tree; it describes the " +
			"tree, not the secrets")
	}
}

func TestCreateGroupRejectsIncompleteInput(t *testing.T) {
	leaf, _, _ := creatorLeaf(t)
	good := randomBytes(t, suiteUnderTest.HashSize())

	cases := map[string]CreateGroupSpec{
		"no creator": {
			Suite: suiteUnderTest, GroupID: []byte("g"), EpochSecret: good,
		},
		"no group ID": {
			Suite: suiteUnderTest, Creator: leaf, EpochSecret: good,
		},
		"short epoch secret": {
			Suite: suiteUnderTest, GroupID: []byte("g"), Creator: leaf,
			EpochSecret: make([]byte, suiteUnderTest.HashSize()-1),
		},
		"long epoch secret": {
			Suite: suiteUnderTest, GroupID: []byte("g"), Creator: leaf,
			EpochSecret: make([]byte, suiteUnderTest.HashSize()+1),
		},
		"no epoch secret at all": {
			Suite: suiteUnderTest, GroupID: []byte("g"), Creator: leaf,
		},
	}

	for name, spec := range cases {
		if _, err := CreateGroup(spec); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
