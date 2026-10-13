package mobile

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// Whether a KeyPackage and the private key returned beside it are a pair.
//
// This needs no group, no commit and no Welcome: it asks one question of one function. The
// joining member ends up holding a private key that does not match its leaf in the tree, the
// tree itself is right, and this is the only step between those two facts that has not been
// checked by VALUE — an earlier round read the assignments and concluded they were consistent,
// which is not the same as reading the values.

func TestTheKeyPackageAndItsReturnedPrivateKeyAreAPair(t *testing.T) {
	identity := testIdentityJSON(t)
	suite := crypto.CipherSuite(GroupCipherSuite)

	generated, err := GroupKeyPackage(identity)
	if err != nil {
		t.Fatalf("GroupKeyPackage: %v", err)
	}

	_ = suite

	// The public key the KeyPackage publishes.
	raw, err := hex.DecodeString(generated.KeyPackageHex)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := messages.ParseKeyPackage(mlstls.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	inKeyPackage := keyPackage.LeafNode.EncryptionKey

	// The comparison below is against the PARSED KeyPackage, not the one that was built. A codec
	// that altered the leaf on the way out and back would look exactly like a private key that
	// does not match — so the round trip is checked first, and byte for byte.
	reencoded, err := messages.MarshalKeyPackage(keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reencoded) {
		t.Fatal("the KeyPackage does not survive a round trip byte for byte, so the leaf parsed " +
			"here is not the leaf that was built, and the mismatch this test reports is a CODEC " +
			"fault rather than a key fault")
	}

	// The public key the returned private key belongs to.
	//
	// This is X25519 SCALAR MULTIPLICATION, not DeriveKeyPair. An earlier version of this test fed
	// the private key back into DeriveKeyPair, whose argument is an ikm to derive FROM — so it
	// produced a third, unrelated key pair, and the test reported a mismatch no matter what the
	// code did. Nine rounds of conclusions rested on that: an alarm that is always true says
	// nothing, and this one was.
	private, err := hex.DecodeString(generated.LeafKeyPrivateHex)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatalf("the returned private key is not a valid X25519 scalar: %v", err)
	}
	fromReturned := priv.PublicKey().Bytes()

	t.Logf("leaf key in the KeyPackage   = %x", inKeyPackage)
	t.Logf("public of the returned key   = %x", fromReturned)
	t.Logf("init key in the KeyPackage   = %x", keyPackage.InitKey)

	// For completeness: the init key must NOT be the leaf key either way.
	if bytes.Equal(keyPackage.InitKey, inKeyPackage) {
		t.Fatal("the KeyPackage's init key is the same as its leaf key, so the two roles share " +
			"one key")
	}

	if !bytes.Equal(inKeyPackage, fromReturned) {
		t.Fatal("the private key returned beside this KeyPackage does NOT belong to the leaf the " +
			"KeyPackage publishes. A member that keeps it will publish one key and hold another, " +
			"and the difference is invisible until somebody tries to send it a path secret.")
	}
}

// Whether deriving a key pair from the same input twice gives the same answer.
//
// Everything else has been ruled out by measurement: the tree holds the leaf the KeyPackage
// describes, the binding passes the private key it was given, newKeyPackage and leafNodeFor both
// use the values they are handed, and the KeyPackage survives a round trip byte for byte. Yet
// the public key derived from a private key is not the public key that was published beside it.
//
// That leaves one possibility, and it is the one the whole scheme rests on: DeriveKeyPair must be
// deterministic. Every member rebuilds the same tree from the same node secrets, and a member
// that derived a different key pair each time could not.
func TestDeriveKeyPairIsDeterministic(t *testing.T) {
	suite := crypto.CipherSuite(GroupCipherSuite)
	_ = suite

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	firstPrivate, firstPublic, err := crypto.DeriveKeyPair(seed, suite)
	if err != nil {
		t.Fatal(err)
	}
	secondPrivate, secondPublic, err := crypto.DeriveKeyPair(seed, suite)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("first  private = %x", firstPrivate)
	t.Logf("second private = %x", secondPrivate)
	t.Logf("first  public  = %x", firstPublic)
	t.Logf("second public  = %x", secondPublic)

	if !bytes.Equal(firstPrivate, secondPrivate) {
		t.Fatal("DeriveKeyPair returned two DIFFERENT PRIVATE keys for the same input. A node " +
			"secret therefore does not determine a key pair, and no member can rebuild the tree " +
			"another member built")
	}
	if !bytes.Equal(firstPublic, secondPublic) {
		t.Fatal("DeriveKeyPair returned two DIFFERENT PUBLIC keys for the same input")
	}
}
