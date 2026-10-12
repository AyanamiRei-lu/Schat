package messages

import (
	"bytes"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// Welcome: the message that lets a new member in.
//
// There are no official vectors for it, so the evidence is a round trip plus the negatives —
// and the negative that matters most here is the CONTEXT. The specification uses the encrypted
// GroupInfo as the HPKE context, which is unusual enough that a reader expects the empty string
// or the group context instead. An implementation that got it wrong would encrypt and decrypt
// against itself flawlessly and agree with nobody else, so the only way to catch it is to try
// opening with the wrong context and require a failure.

func welcomeKeyPair(t *testing.T, label string) (priv, pub []byte) {
	t.Helper()
	seed := make([]byte, 32)
	copy(seed, []byte(label))
	priv, pub, err := crypto.DeriveKeyPair(seed, suiteUnderTest)
	if err != nil {
		t.Fatalf("DeriveKeyPair(%s): %v", label, err)
	}
	return priv, pub
}

func sampleGroupSecrets(t *testing.T) *GroupSecrets {
	t.Helper()
	return &GroupSecrets{
		JoinerSecret: bytes.Repeat([]byte{0x7A}, suiteUnderTest.HashSize()),
		PathSecret:   &PathSecret{PathSecret: bytes.Repeat([]byte{0x3C}, suiteUnderTest.HashSize())},
		PSKs: []PreSharedKeyID{{
			Type:  PSKTypeExternal,
			ID:    []byte("psk-id"),
			Nonce: bytes.Repeat([]byte{0x11}, suiteUnderTest.HashSize()),
		}},
	}
}

func TestGroupSecretsRoundTrip(t *testing.T) {
	original := sampleGroupSecrets(t)

	encoded, err := MarshalGroupSecrets(original)
	if err != nil {
		t.Fatalf("MarshalGroupSecrets: %v", err)
	}
	decoded, err := ParseGroupSecrets(mlstls.NewReader(encoded))
	if err != nil {
		t.Fatalf("decoding its own output: %v", err)
	}
	reencoded, err := MarshalGroupSecrets(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("the round trip changed the bytes")
	}

	if !bytes.Equal(decoded.JoinerSecret, original.JoinerSecret) {
		t.Fatal("the joiner secret did not survive")
	}
	if decoded.PathSecret == nil || !bytes.Equal(decoded.PathSecret.PathSecret, original.PathSecret.PathSecret) {
		t.Fatal("the path secret did not survive")
	}
	if len(decoded.PSKs) != 1 || !bytes.Equal(decoded.PSKs[0].ID, []byte("psk-id")) {
		t.Fatal("the PSK identifier did not survive")
	}
	if !bytes.Equal(decoded.PSKs[0].Nonce, original.PSKs[0].Nonce) {
		t.Fatal("the PSK nonce did not survive")
	}
}

// TestAnAbsentPathSecretIsNotAnEmptyOne pins the optional encoding. "No path secret" and "a
// path secret of length zero" are different on the wire — a presence byte against a present
// byte followed by a zero length — and a decoder that conflated them would accept a Welcome
// whose secrets are silently different from what the sender wrote.
func TestAnAbsentPathSecretIsNotAnEmptyOne(t *testing.T) {
	withoutPath := &GroupSecrets{JoinerSecret: bytes.Repeat([]byte{0x01}, 32)}

	withEmptyPath := &GroupSecrets{
		JoinerSecret: bytes.Repeat([]byte{0x01}, 32),
		PathSecret:   &PathSecret{PathSecret: []byte{}},
	}

	a, err := MarshalGroupSecrets(withoutPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalGroupSecrets(withEmptyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("an absent path secret and an empty one encode identically, so the distinction " +
			"the optional field exists to make is lost")
	}

	decodedA, err := ParseGroupSecrets(mlstls.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	if decodedA.PathSecret != nil {
		t.Fatal("an absent path secret decoded as present")
	}

	decodedB, err := ParseGroupSecrets(mlstls.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if decodedB.PathSecret == nil || len(decodedB.PathSecret.PathSecret) != 0 {
		t.Fatal("an empty path secret did not decode as present and empty")
	}
}

func TestResumptionPSKIdentifierRoundTrips(t *testing.T) {
	secrets := &GroupSecrets{
		JoinerSecret: bytes.Repeat([]byte{0x05}, 32),
		PSKs: []PreSharedKeyID{{
			Type:    PSKTypeResumption,
			Usage:   ResumptionPSKUsageBranch,
			GroupID: []byte("a-group"),
			Epoch:   42,
			Nonce:   bytes.Repeat([]byte{0x22}, 32),
		}},
	}

	encoded, err := MarshalGroupSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseGroupSecrets(mlstls.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.PSKs) != 1 {
		t.Fatalf("decoded %d PSK identifiers, want 1", len(decoded.PSKs))
	}
	psk := decoded.PSKs[0]
	if psk.Type != PSKTypeResumption || psk.Usage != ResumptionPSKUsageBranch ||
		!bytes.Equal(psk.GroupID, []byte("a-group")) || psk.Epoch != 42 {
		t.Fatalf("the resumption PSK identifier did not survive: %+v", psk)
	}
}

// TestWelcomeSecretsAreBoundToTheirGroupInfo is the test that stands in for the vector this
// message does not have.
//
// The HPKE context is the encrypted GroupInfo. Sealing under one GroupInfo and opening under
// another must fail: if it did not, the secrets from one Welcome could be recombined with the
// GroupInfo of a different epoch, and a member could be handed the keys of a group it was never
// added to.
func TestWelcomeSecretsAreBoundToTheirGroupInfo(t *testing.T) {
	initPrivate, initPublic := welcomeKeyPair(t, "welcome-init")

	groupInfo := []byte("the encrypted group info for epoch 1")
	otherGroupInfo := []byte("the encrypted group info for epoch 2")

	sealed, err := EncryptGroupSecrets(initPublic, groupInfo, sampleGroupSecrets(t), suiteUnderTest)
	if err != nil {
		t.Fatalf("EncryptGroupSecrets: %v", err)
	}

	decoded, err := DecryptGroupSecrets(initPrivate, groupInfo, sealed, suiteUnderTest)
	if err != nil {
		t.Fatalf("the intended member could not open its own secrets: %v", err)
	}
	if len(decoded.JoinerSecret) == 0 {
		t.Fatal("the joiner secret came back empty")
	}

	if _, err := DecryptGroupSecrets(initPrivate, otherGroupInfo, sealed, suiteUnderTest); err == nil {
		t.Fatal("the secrets opened under a DIFFERENT group info, so they are not bound to it and " +
			"one Welcome's secrets could be recombined with another epoch's GroupInfo")
	}

	// The empty context is the mistake a reader is most likely to make. Refusing it at sealing
	// time is better than producing a message that only its author can open.
	if _, err := EncryptGroupSecrets(initPublic, nil, sampleGroupSecrets(t), suiteUnderTest); err == nil {
		t.Fatal("secrets were sealed with no group info, which the specification uses as the " +
			"HPKE context")
	}

	// The wrong key must not open it either.
	otherPrivate, _ := welcomeKeyPair(t, "somebody-else")
	if _, err := DecryptGroupSecrets(otherPrivate, groupInfo, sealed, suiteUnderTest); err == nil {
		t.Fatal("a different member's init key opened the secrets")
	}

	// A tampered ciphertext must fail rather than return a truncated secret.
	broken := sealed
	broken.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
	broken.Ciphertext[0] ^= 0x01
	if _, err := DecryptGroupSecrets(initPrivate, groupInfo, broken, suiteUnderTest); err == nil {
		t.Fatal("a ciphertext with a flipped bit opened")
	}
}

func TestWelcomeRoundTripWithSeveralNewMembers(t *testing.T) {
	groupInfo := []byte("encrypted group info")

	welcome := &Welcome{
		CipherSuite:        uint16(suiteUnderTest),
		EncryptedGroupInfo: groupInfo,
	}

	for _, label := range []string{"member-c", "member-d"} {
		_, initPublic := welcomeKeyPair(t, "init-"+label)
		sealed, err := EncryptGroupSecrets(initPublic, groupInfo, sampleGroupSecrets(t), suiteUnderTest)
		if err != nil {
			t.Fatal(err)
		}
		welcome.Secrets = append(welcome.Secrets, EncryptedGroupSecrets{
			NewMember:             KeyPackageRef(bytes.Repeat([]byte{0x09}, 32)),
			EncryptedGroupSecrets: sealed,
		})
	}

	encoded, err := MarshalWelcome(welcome)
	if err != nil {
		t.Fatalf("MarshalWelcome: %v", err)
	}
	decoded, err := ParseWelcome(mlstls.NewReader(encoded))
	if err != nil {
		t.Fatalf("decoding its own output: %v", err)
	}

	if len(decoded.Secrets) != 2 {
		t.Fatalf("decoded %d entries, want 2", len(decoded.Secrets))
	}
	if !bytes.Equal(decoded.EncryptedGroupInfo, groupInfo) {
		t.Fatal("the encrypted group info did not survive")
	}
	if decoded.CipherSuite != uint16(suiteUnderTest) {
		t.Fatal("the cipher suite did not survive")
	}

	reencoded, err := MarshalWelcome(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("the round trip changed the bytes")
	}
}
