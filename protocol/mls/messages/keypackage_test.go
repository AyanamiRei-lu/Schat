package messages

import (
	"bytes"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// KeyPackages: the structure an Add proposal carries, and the checks that decide whether one
// may be used.
//
// There are no official vectors for it, so the evidence is a round trip plus the negatives. The
// negatives matter more here than usual: a KeyPackage is what lets a stranger into a group, and
// every check below is one that, if skipped, admits a member whose keys nothing in the group
// can use — or admits one whose init key is the key protecting its traffic.

func signedKeyPackage(t *testing.T) *KeyPackage {
	t.Helper()

	priv, pub := testKeyPair(t, "keypackage-signer")

	leaf := sampleLeafNode()
	leaf.SignatureKey = pub

	kp := &KeyPackage{
		Version:     1,
		CipherSuite: 1,
		// Deliberately different from the leaf's encryption key: they protect different things
		// and VerifyKeyPackage refuses a package that reuses one for the other.
		InitKey:    bytes.Repeat([]byte{0x5E}, 32),
		LeafNode:   leaf,
		Extensions: []tree.Extension{{Type: 3, Data: []byte{0x01, 0x02}}},
	}

	signature, err := SignKeyPackage(kp, priv, suiteUnderTest)
	if err != nil {
		t.Fatalf("SignKeyPackage: %v", err)
	}
	kp.Signature = signature
	return kp
}

func TestKeyPackageRoundTripAndVerification(t *testing.T) {
	kp := signedKeyPackage(t)

	if err := VerifyKeyPackage(kp, 1, 1, suiteUnderTest); err != nil {
		t.Fatalf("a package that was just signed did not verify: %v", err)
	}

	encoded, err := MarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("MarshalKeyPackage: %v", err)
	}

	decoded, err := ParseKeyPackage(mlstls.NewReader(encoded))
	if err != nil {
		t.Fatalf("decoding its own output: %v", err)
	}

	reencoded, err := MarshalKeyPackage(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("the round trip changed the bytes")
	}

	// The decoded package must still verify, which exercises the leaf's own encoding inside it.
	if err := VerifyKeyPackage(decoded, 1, 1, suiteUnderTest); err != nil {
		t.Fatalf("the decoded package no longer verifies: %v", err)
	}
	if len(decoded.Extensions) != 1 || decoded.Extensions[0].Type != 3 {
		t.Fatal("the extension vector did not survive")
	}
	if !bytes.Equal(decoded.InitKey, kp.InitKey) {
		t.Fatal("the init key did not survive")
	}
}

func TestVerifyKeyPackageRejectsWhatItMust(t *testing.T) {
	base := signedKeyPackage(t)

	// Another protocol version or ciphersuite describes a different group.
	if err := VerifyKeyPackage(base, 2, 1, suiteUnderTest); err == nil {
		t.Fatal("a package for another protocol version was accepted")
	}
	if err := VerifyKeyPackage(base, 1, 3, suiteUnderTest); err == nil {
		t.Fatal("a package for another cipher suite was accepted")
	}

	// The init key and the leaf's encryption key must differ: sharing one ties the Welcome's
	// protection to the key protecting the member's traffic.
	reused := *base
	reusedLeaf := *base.LeafNode
	reusedLeaf.EncryptionKey = base.InitKey
	reused.LeafNode = &reusedLeaf
	if err := VerifyKeyPackage(&reused, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("a package that reuses its leaf encryption key as its init key was accepted")
	}

	// Unsigned.
	unsigned := *base
	unsigned.Signature = nil
	if err := VerifyKeyPackage(&unsigned, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("an unsigned package was accepted")
	}

	// A tampered leaf must break the signature: the signature covers the leaf, so changing the
	// key the member will be added under must not go unnoticed.
	tampered := *base
	tamperedLeaf := *base.LeafNode
	tamperedLeaf.EncryptionKey = bytes.Repeat([]byte{0x99}, 32)
	tampered.LeafNode = &tamperedLeaf
	if err := VerifyKeyPackage(&tampered, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("a package whose leaf was altered verified, so the signature does not cover the " +
			"leaf the member will be added under")
	}

	// A tampered init key must break it too, or the Welcome would go to the wrong key.
	tamperedInit := *base
	tamperedInit.InitKey = bytes.Repeat([]byte{0x88}, 32)
	if err := VerifyKeyPackage(&tamperedInit, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("a package whose init key was altered verified")
	}

	// A flipped bit in the signature.
	broken := *base
	brokenSig := append([]byte(nil), base.Signature...)
	brokenSig[0] ^= 0x01
	broken.Signature = brokenSig
	if err := VerifyKeyPackage(&broken, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("a signature with a flipped bit verified")
	}

	// A package with no leaf at all.
	if err := VerifyKeyPackage(&KeyPackage{Version: 1, CipherSuite: 1, InitKey: base.InitKey},
		1, 1, suiteUnderTest); err == nil {
		t.Fatal("a package with no leaf node was accepted")
	}
	if err := VerifyKeyPackage(nil, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("a nil package was accepted")
	}

	// An empty init key must be refused before anything else looks at it.
	noInit := *base
	noInit.InitKey = nil
	if err := VerifyKeyPackage(&noInit, 1, 1, suiteUnderTest); err == nil {
		t.Fatal("a package with no init key was accepted")
	}
}

func TestKeyPackageReferenceMatchesTheSpecifiedConstruction(t *testing.T) {
	kp := signedKeyPackage(t)

	got, err := MakeKeyPackageReference(kp, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := MarshalKeyPackage(kp)
	if err != nil {
		t.Fatal(err)
	}
	want, err := crypto.RefHash("MLS 1.0 KeyPackage Reference", encoded, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the reference is not RefHash(\"MLS 1.0 KeyPackage Reference\", package):\n"+
			"  got  %x\n  want %x", got, want)
	}

	// The label is load-bearing: without the prefix the value must differ, or the constant
	// could be wrong and this test would still pass.
	withoutLabel, err := crypto.RefHash("KeyPackage Reference", encoded, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, withoutLabel) {
		t.Fatal("the reference ignores its label")
	}

	// Two different packages must have different references, since a reference identifies one
	// published package rather than one client.
	other := signedKeyPackage(t)
	other.InitKey = bytes.Repeat([]byte{0x11}, 32)
	otherSig, err := SignKeyPackage(other, nil, suiteUnderTest)
	if err == nil {
		other.Signature = otherSig
	}
	otherRef, err := MakeKeyPackageReference(other, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, otherRef) {
		t.Fatal("two different packages share a reference")
	}
}

func TestSignKeyPackageRefusesANonEd25519Suite(t *testing.T) {
	kp := signedKeyPackage(t)

	// Suite 0x0002 signs with ECDSA. Producing an Ed25519 signature under it would succeed
	// locally and be rejected by every other implementation, with nothing in the failure
	// pointing at the signature scheme.
	if _, err := SignKeyPackage(kp, bytes.Repeat([]byte{0x01}, 32), crypto.CipherSuite(0x0002)); err == nil {
		t.Fatal("a package was signed for a suite whose signature scheme is not Ed25519")
	}
}
