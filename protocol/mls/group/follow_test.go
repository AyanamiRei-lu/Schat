package group

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/tree"
)

// A member following TWO commits in a row.
//
// # Why one commit is not enough
//
// Every end-to-end test before this one let a member process a single commit, and supplied the
// applier from the test itself — so what they proved is that a member holding the key it joined
// with can read the next thing that happens. That is not following a group.
//
// A commit REPLACES the keys along its path. The second commit is encrypted under the keys the
// FIRST one installed, so a member that has not updated its own private state cannot open it:
// its old key is simply the wrong key. A test that used the original key for the second commit
// would fail at the decryption, which is exactly the property being asserted.
//
// This is the receiver side's only real evidence. Everything else about it — that it compiles,
// that the derivation matches the specification — says the code is plausible, not that a member
// can actually keep up.

// processAsMember applies a commit on behalf of a member, using the private state that member
// currently holds.
//
// The applier reads the member's leaf key from ITS OWN PrivateNodes rather than from a captured
// variable: that is the whole point. A test that reached for the original key would pass while
// the code under test did nothing.
func processAsMember(
	t *testing.T,
	epoch *Epoch,
	myLeaf uint32,
	created *CreatedCommit,
	senderSignatureKey []byte,
	commitSecret []byte,
) *Epoch {
	t.Helper()

	contextBytes, err := epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	originalHashes, err := tree.TreeHashes(epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	applier := func(_ uint32, ct tree.HPKECiphertext) ([]byte, bool) {
		leafKey := epoch.PrivateNodes[2*myLeaf]
		if len(leafKey) == 0 {
			return nil, false
		}
		secret, err := crypto.DecryptWithLabel(leafKey, "UpdatePathNode", contextBytes,
			ct.KemOutput, ct.Ciphertext, suiteUnderTest)
		if err != nil {
			return nil, false
		}
		return secret, true
	}

	in := created.AsInput(senderSignatureKey, nil, applier, originalHashes, nil)
	// The leaf of the member PROCESSING the commit — not the sender's.
	in.MyLeaf = myLeaf

	next, err := epoch.ProcessCommit(in)
	if err != nil {
		t.Fatalf("leaf %d could not process a commit: %v", myLeaf, err)
	}
	return next
}

func TestAMemberFollowsTwoCommitsInARow(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")

	// B is leaf 1, so its leaf's NODE index is 2. The two numbering spaces differ by a factor of
	// two, and mixing them yields a member that holds the right key under the wrong name.
	bEpoch := f.epoch
	bEpoch.PrivateNodes = map[uint32][]byte{2: f.bLeafPriv}

	// --- the first commit: A updates itself ------------------------------------------------
	_, aLeafPublic1 := hpkeKeyFor(t, "leaf-a-epoch-1")
	pathSecret1 := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret1); err != nil {
		t.Fatal(err)
	}

	first, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		NewLeafNode: &tree.LeafNode{
			EncryptionKey: aLeafPublic1,
			SignatureKey:  aPublic,
			Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
			Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        tree.LeafNodeSourceUpdate,
		},
		PathSecret: pathSecret1,
	})
	if err != nil {
		t.Fatalf("the first commit could not be created: %v", err)
	}

	bEpoch = processAsMember(t, bEpoch, 1, first, []byte(aPublic), f.commitSec)

	if !bytes.Equal(bEpoch.Secrets.EpochAuthenticator, first.Next.Secrets.EpochAuthenticator) {
		t.Fatal("B did not reach the same epoch as the committer after the first commit")
	}
	// The update must have replaced B's private state. If it did not, the next step fails — and
	// that is what this test is for.
	if len(bEpoch.PrivateNodes) == 0 {
		t.Fatal("B processed a commit and derived no private nodes, so it cannot follow the next one")
	}

	// --- the second commit: A adds C, from the epoch the first one opened ------------------
	keyPackage, _ := memberCKeyPackage(t)
	_, aLeafPublic2 := hpkeKeyFor(t, "leaf-a-epoch-2")
	pathSecret2 := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret2); err != nil {
		t.Fatal(err)
	}
	commitSecret2 := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(commitSecret2); err != nil {
		t.Fatal(err)
	}

	second, err := first.Next.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		Proposals: []*messages.ProposalOrRef{{
			Type:     messages.ProposalOrRefTypeProposal,
			Proposal: &messages.Proposal{Type: messages.ProposalTypeAdd, Add: &messages.Add{KeyPackage: keyPackage}},
		}},
		NewLeafNode: &tree.LeafNode{
			EncryptionKey: aLeafPublic2,
			SignatureKey:  aPublic,
			Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
			Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        tree.LeafNodeSourceUpdate,
		},
		PathSecret: pathSecret2,
	})
	if err != nil {
		t.Fatalf("the second commit could not be created: %v", err)
	}

	// The crux: B processes this one with the state the FIRST commit left it. Its original key is
	// the wrong key now, so a member that had not updated itself fails here.
	bEpoch = processAsMember(t, bEpoch, 1, second, []byte(aPublic), commitSecret2)

	if !bytes.Equal(bEpoch.Secrets.EpochAuthenticator, second.Next.Secrets.EpochAuthenticator) {
		t.Fatal("B reached a different epoch than the committer after following two commits, so " +
			"it cannot keep up with a group that changes")
	}
	if bEpoch.Number != second.Next.Number {
		t.Fatalf("B is at epoch %d and the committer at %d", bEpoch.Number, second.Next.Number)
	}

	t.Logf("B followed two commits and reached epoch %d, deriving %d private nodes on the way",
		bEpoch.Number, len(bEpoch.PrivateNodes))
}
