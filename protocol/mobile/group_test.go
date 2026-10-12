package mobile

import (
	"encoding/hex"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/messages"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// The group binding: what crosses into Kotlin, checked on the Go side.
//
// The binding is thin, and thin layers are where a mistake is least visible: it composes calls
// that are each verified, so a defect here is one of wiring — a key used in the wrong role, a
// state handed back that does not restore, a suite passed in one place and assumed in another.
// These tests exercise the composition rather than the parts.

func testIdentityJSON(t *testing.T) string {
	t.Helper()
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	blob, err := IdentityToJSON(identity)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}
	return blob
}

func TestGroupKeyPackageIsVerifiable(t *testing.T) {
	// ONE identity, reused: GenerateIdentity draws a fresh one every call, so comparing a
	// KeyPackage against a second call would compare it against a different person.
	identityJSON := testIdentityJSON(t)
	generated, err := GroupKeyPackage(identityJSON)
	raw := generated.KeyPackageHex
	if err != nil {
		t.Fatalf("GroupKeyPackage: %v", err)
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("the KeyPackage is not hex: %v", err)
	}

	// It must parse and its signature must verify against the identity that produced it. A
	// KeyPackage that cannot be verified is one nobody can safely ADD, so this is the property
	// that makes the function useful rather than merely non-crashing.
	keyPackage, err := messages.ParseKeyPackage(mlstls.NewReader(decoded))
	if err != nil {
		t.Fatalf("the KeyPackage does not parse: %v", err)
	}
	if err := messages.VerifyKeyPackage(keyPackage, 1, GroupCipherSuite,
		crypto.CipherSuite(GroupCipherSuite)); err != nil {
		t.Fatalf("the KeyPackage signature does not verify: %v", err)
	}

	// The leaf's signature key is the IDENTITY's, which is what ties the group member to the
	// contact the user already verified.
	identity, err := IdentityFromJSON(identityJSON)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(identity.SigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyPackage.LeafNode.SignatureKey) != string(want) {
		t.Fatal("the leaf's signature key is not the identity's, so a group member would not be " +
			"the contact the user verified")
	}

	// The init key must NOT be the leaf's encryption key: the init key exists to receive the
	// Welcome, and sharing one key between the two roles would put the epoch's traffic under a
	// key that was published.
	if string(keyPackage.InitKey) == string(keyPackage.LeafNode.EncryptionKey) {
		t.Fatal("the init key and the leaf encryption key are the same, so a published key also " +
			"protects the group's traffic")
	}

	// Two calls must not produce the same keys: every KeyPackage is a fresh one.
	otherGenerated, err := GroupKeyPackage(identityJSON)
	if err != nil {
		t.Fatal(err)
	}
	other := otherGenerated.KeyPackageHex
	otherDecoded, err := hex.DecodeString(other)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPackage, err := messages.ParseKeyPackage(mlstls.NewReader(otherDecoded))
	if err != nil {
		t.Fatal(err)
	}
	if string(otherKeyPackage.InitKey) == string(keyPackage.InitKey) {
		t.Fatal("two KeyPackages shared an init key, so the keys are not being drawn fresh")
	}
}

func TestGroupCreateAndSummarise(t *testing.T) {
	state, err := GroupCreate(testIdentityJSON(t), "6d792d67726f7570") // "my-group"
	if err != nil {
		t.Fatalf("GroupCreate: %v", err)
	}

	summary, err := GroupStateSummary(state)
	if err != nil {
		t.Fatalf("GroupStateSummary: %v", err)
	}

	if summary.Epoch != 0 {
		t.Fatalf("a new group is at epoch %d, want 0", summary.Epoch)
	}
	if summary.CipherSuite != GroupCipherSuite {
		t.Fatalf("the group reports suite %#04x", summary.CipherSuite)
	}
	if summary.GroupIDHex != "6d792d67726f7570" {
		t.Fatalf("the group id came back as %q", summary.GroupIDHex)
	}
	if summary.MemberCount != 1 {
		t.Fatalf("a new group has %d members, want 1", summary.MemberCount)
	}
	if summary.LeafCount != 1 {
		t.Fatalf("a one-member group has %d leaves, want 1 — a group of one is a single node, "+
			"which is why its first commit cannot carry an update path", summary.LeafCount)
	}
}

func TestGroupBindingRejectsBadInput(t *testing.T) {
	good := testIdentityJSON(t)

	if _, err := GroupKeyPackage("not json"); err == nil {
		t.Fatal("a KeyPackage was built from a non-identity")
	}
	if _, err := GroupCreate(good, "zz"); err == nil {
		t.Fatal("a group was created with a non-hex id")
	}
	if _, err := GroupCreate(good, ""); err == nil {
		t.Fatal("a group was created with no id")
	}
	if _, err := GroupStateSummary("not json"); err == nil {
		t.Fatal("a summary was produced from a non-snapshot")
	}
	if _, err := GroupStateSummary(""); err == nil {
		t.Fatal("a summary was produced from an empty state")
	}
}
