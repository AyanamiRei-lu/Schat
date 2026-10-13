package group

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// A third member joining through a Welcome.
//
// # Why this test is the one that says whether adding works
//
// Every piece of the joiner's path had been written and none of it had ever run together:
// decrypting the group secrets, deriving the welcome secret, opening the GroupInfo, reading the
// group context out of it, deriving the epoch, and checking the confirmation tag. A defect that
// lives BETWEEN two of those pieces is invisible to a test of either one — and the pieces were
// each verified only in the sense of compiling.
//
// The assertion that matters is the last one: A, B and C must hold byte-identical epoch
// secrets, with C having derived its own from nothing but the Welcome. Everything before it
// checks a step; that one checks that all three ended up in the same group.

// aesGCMSeal and aesGCMOpen are what a real client does with the welcome key and nonce: the
// GroupInfo is protected with the suite's AEAD under those two values, with no associated data.
// The suite under test is AES-128-GCM, so the standard library is the implementation.
func aesGCMSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func aesGCMOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// memberCKeyPackage builds a KeyPackage whose init key the test also holds the private half of,
// so that the Welcome can actually be opened. add_test.go's helper does not need that because
// nothing there reads the Welcome.
func memberCKeyPackage(t *testing.T) (*messages.KeyPackage, []byte) {
	t.Helper()

	signingPrivate, signingPublic := signerFor("keypackage-member-c")
	_, leafPublic := hpkeKeyFor(t, "leaf-member-c")
	initPrivate, initPublic := hpkeKeyFor(t, "init-member-c")

	kp := &messages.KeyPackage{
		Version:     1,
		CipherSuite: uint16(suiteUnderTest),
		InitKey:     initPublic,
		LeafNode: &tree.LeafNode{
			EncryptionKey: leafPublic,
			SignatureKey:  signingPublic,
			Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("C")},
			Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        tree.LeafNodeSourceKeyPackage,
			Lifetime:      &tree.Lifetime{NotBefore: 0, NotAfter: 1 << 40},
		},
	}

	signature, err := messages.SignKeyPackage(kp, signingPrivate, suiteUnderTest)
	if err != nil {
		t.Fatalf("signing C's KeyPackage: %v", err)
	}
	kp.Signature = signature
	return kp, initPrivate
}

func TestThreeMembersConvergeThroughAWelcome(t *testing.T) {
	f := twoMemberGroup(t)

	aPrivate, aPublic := signerFor("member-a")
	_, newLeafPub := hpkeKeyFor(t, "leaf-a-epoch-1")

	keyPackage, cInitPrivate := memberCKeyPackage(t)

	pathSecret := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(pathSecret); err != nil {
		t.Fatal(err)
	}

	// A commits the addition.
	created, err := f.epoch.CreateCommit(CommitSpec{
		WireFormat:       messages.WireFormatPublicMessage,
		SenderLeaf:       0,
		SenderSigningKey: aPrivate,
		Proposals: []*messages.ProposalOrRef{{
			Type:     messages.ProposalOrRefTypeProposal,
			Proposal: &messages.Proposal{Type: messages.ProposalTypeAdd, Add: &messages.Add{KeyPackage: keyPackage}},
		}},
		NewLeafNode: &tree.LeafNode{
			EncryptionKey: newLeafPub,
			SignatureKey:  aPublic,
			Credential:    tree.Credential{Type: tree.CredentialTypeBasic, Identity: []byte("A")},
			Capabilities:  tree.Capabilities{Versions: []uint16{1}, CipherSuites: []uint16{1}},
			Source:        tree.LeafNodeSourceUpdate,
		},
		PathSecret: pathSecret,
	})
	if err != nil {
		t.Fatalf("CreateCommit: %v", err)
	}

	// C's leaf is at the right edge of the extended tree.
	const cLeafIndex = 3
	if created.Next.Tree[2*cLeafIndex] == nil ||
		!bytes.Equal(created.Next.Tree[2*cLeafIndex].Leaf.EncryptionKey, keyPackage.LeafNode.EncryptionKey) {
		t.Fatal("the commit did not place C's leaf at the right edge of the extended tree")
	}

	// The GroupInfo for the new epoch: the context, the confirmation tag A computed, and A's
	// signature over both.
	contextBytes, err := created.Next.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	groupInfo := &messages.GroupInfo{
		GroupContext:    contextBytes,
		ConfirmationTag: created.ConfirmationTag,
		Signer:          0,
	}
	signature, err := messages.SignGroupInfo(groupInfo, aPrivate)
	if err != nil {
		t.Fatalf("signing the GroupInfo: %v", err)
	}
	groupInfo.Signature = signature

	groupInfoBytes, err := messages.MarshalGroupInfo(groupInfo)
	if err != nil {
		t.Fatal(err)
	}

	// The GroupInfo is protected with the key and nonce derived from the welcome secret — the
	// same secret the Welcome's group secrets let a joiner derive.
	welcomeKey, welcomeNonce, err := WelcomeKeyNonce(created.Next.Secrets.WelcomeSecret, suiteUnderTest)
	if err != nil {
		t.Fatalf("WelcomeKeyNonce: %v", err)
	}
	encryptedGroupInfo, err := aesGCMSeal(welcomeKey, welcomeNonce, groupInfoBytes)
	if err != nil {
		t.Fatal(err)
	}

	keyPackageRef, err := messages.MakeKeyPackageReference(keyPackage, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	welcome, err := BuildWelcome(WelcomeSpec{
		Suite:              suiteUnderTest,
		CommitterLeaf:      0,
		NewMembers:         []NewMember{{LeafIndex: cLeafIndex, InitKey: keyPackage.InitKey, KeyPackageRef: keyPackageRef}},
		PathSecretsByNode:  created.KnownSecrets,
		LeafCount:          4,
		NewEpochSecrets:    created.Next.Secrets,
		EncryptedGroupInfo: encryptedGroupInfo,
	})
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	if len(welcome.Secrets) != 1 {
		t.Fatalf("the Welcome has %d entries, want 1", len(welcome.Secrets))
	}

	// C accepts it, with nothing but its own init key and the tree.
	joined, err := AcceptWelcome(AcceptWelcomeSpec{
		Suite:          suiteUnderTest,
		Welcome:        welcome,
		Entry:          welcome.Secrets[0],
		InitKeyPrivate: cInitPrivate,
		Tree:           created.Next.Tree,
		DecryptGroupInfo: func(key, nonce, ciphertext []byte) ([]byte, error) {
			return aesGCMOpen(key, nonce, ciphertext)
		},
	})
	if err != nil {
		t.Fatalf("C could not accept the Welcome: %v", err)
	}

	// And all three sides hold the same epoch.
	if joined.Epoch.Number != created.Next.Number {
		t.Fatalf("C joined epoch %d but the commit opened %d", joined.Epoch.Number, created.Next.Number)
	}
	for name, pair := range map[string][2][]byte{
		"encryption secret":   {joined.Epoch.Secrets.EncryptionSecret, created.Next.Secrets.EncryptionSecret},
		"confirmation key":    {joined.Epoch.Secrets.ConfirmationKey, created.Next.Secrets.ConfirmationKey},
		"init secret":         {joined.Epoch.Secrets.InitSecret, created.Next.Secrets.InitSecret},
		"membership key":      {joined.Epoch.Secrets.MembershipKey, created.Next.Secrets.MembershipKey},
		"epoch authenticator": {joined.Epoch.Secrets.EpochAuthenticator, created.Next.Secrets.EpochAuthenticator},
		"sender data secret":  {joined.Epoch.Secrets.SenderDataSecret, created.Next.Secrets.SenderDataSecret},
		"exporter secret":     {joined.Epoch.Secrets.ExporterSecret, created.Next.Secrets.ExporterSecret},
		"tree hash":           {joined.Epoch.Context.TreeHash, created.Next.Context.TreeHash},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("C's %s differs from the committer's, so the Welcome did not deliver the epoch",
				name)
		}
	}

	// B, the member that was already in the group, must reach the same epoch too.
	originalHashes, err := tree.TreeHashes(f.epoch.Tree, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	bContext, err := f.epoch.Context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bNext, err := f.epoch.ProcessCommit(created.AsInput([]byte(aPublic), nil,
		func(member uint32, ct tree.HPKECiphertext) ([]byte, bool) {
			// B holds the key for its own leaf, which is the only path recipient.
			if member != 2 {
				return nil, false
			}
			secret, err := crypto.DecryptWithLabel(f.bLeafPriv, "UpdatePathNode", bContext, ct.KemOutput, ct.Ciphertext, suiteUnderTest)
			if err != nil {
				return nil, false
			}
			return secret, true
		}, originalHashes, nil))
	if err != nil {
		t.Fatalf("B rejected the commit that added C: %v", err)
	}
	if !bytes.Equal(bNext.Secrets.EncryptionSecret, created.Next.Secrets.EncryptionSecret) {
		t.Fatal("B derived a different epoch from the same commit")
	}
	if !bytes.Equal(bNext.Secrets.EncryptionSecret, joined.Epoch.Secrets.EncryptionSecret) {
		t.Fatal("B and C disagree about the epoch, so the Welcome and the commit delivered " +
			"different group state")
	}

	t.Logf("A, B and C all reached epoch %d: C through the Welcome, B through the commit",
		joined.Epoch.Number)
}
