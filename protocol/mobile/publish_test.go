package mobile

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/schat/schat/protocol"
)

// TestPublishBundleJSONCarriesTheWholePool guards the failure this function exists to
// prevent: a directory entry whose one-time pool holds a single prekey. The first peer
// to start a session would drain it, and every peer after that would silently fall back
// to the mode with no forward secrecy — invisibly, on both sides.
func TestPublishBundleJSONCarriesTheWholePool(t *testing.T) {
	responder, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	responderBlob, err := IdentityToJSON(responder)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}

	const poolSize = 5
	storeJSON, err := CreatePreKeyStore(responderBlob, poolSize)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}

	published, err := PublishBundleJSON(storeJSON, responderBlob)
	if err != nil {
		t.Fatalf("PublishBundleJSON: %v", err)
	}

	var got publishBundleJSON
	if err := json.Unmarshal([]byte(published), &got); err != nil {
		t.Fatalf("the published bundle is not valid JSON: %v", err)
	}

	if got.IdentitySigning != responder.SigningPublic {
		t.Fatalf("published identity is %s, want %s", got.IdentitySigning, responder.SigningPublic)
	}
	if len(got.OneTimePreKeys) != poolSize {
		t.Fatalf("published %d one-time prekeys, want %d", len(got.OneTimePreKeys), poolSize)
	}

	seen := make(map[int64]bool, poolSize)
	for _, otp := range got.OneTimePreKeys {
		if seen[otp.ID] {
			t.Fatalf("prekey id %d was published twice", otp.ID)
		}
		seen[otp.ID] = true

		raw, err := hex.DecodeString(otp.Public)
		if err != nil || len(raw) != 32 {
			t.Fatalf("prekey %d is not a 32-byte hex value: %q", otp.ID, otp.Public)
		}
	}

	// The published signature has to verify against the published identity, or no peer
	// could start a session from this bundle.
	signPub, err := hex.DecodeString(got.IdentitySigning)
	if err != nil {
		t.Fatalf("identity is not hex: %v", err)
	}
	spk, err := hex.DecodeString(got.SignedPreKey)
	if err != nil {
		t.Fatalf("signed prekey is not hex: %v", err)
	}
	sig, err := hex.DecodeString(got.SignedPreKeySignature)
	if err != nil {
		t.Fatalf("signature is not hex: %v", err)
	}
	if err := protocol.Verify(signPub, spk, sig); err != nil {
		t.Fatalf("the published bundle signature does not verify: %v", err)
	}

	// Field-name compatibility is the other silent failure mode: the relay parses this
	// JSON into its own Bundle struct, and it hands back the same shape, which the
	// initiator feeds to EstablishSession. Simulate that path exactly — a directory
	// fetch returns at most one prekey — and require a session to come out.
	fetched := got
	fetched.OneTimePreKeys = got.OneTimePreKeys[:1]
	fetchJSON, err := json.Marshal(fetched)
	if err != nil {
		t.Fatalf("re-marshalling the fetched bundle: %v", err)
	}

	initiator, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	initiatorBlob, err := IdentityToJSON(initiator)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}

	session, err := EstablishSession(initiatorBlob, responder.SigningPublic, string(fetchJSON))
	if err != nil {
		t.Fatalf("a bundle produced by PublishBundleJSON was not accepted by "+
			"EstablishSession, so the two ends disagree on the field names: %v", err)
	}
	defer session.Close()

	if len(session.InitMessage()) != protocol.HandshakeInitSize {
		t.Fatalf("initiation is %d bytes, want %d",
			len(session.InitMessage()), protocol.HandshakeInitSize)
	}
}

// TestPublishBundleJSONWithAnEmptyPoolIsStillPublishable pins the degraded mode: a
// drained pool is a legitimate state, not an error, and the bundle must still carry
// everything a handshake needs.
func TestPublishBundleJSONWithAnEmptyPoolIsStillPublishable(t *testing.T) {
	responder, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	responderBlob, err := IdentityToJSON(responder)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}

	storeJSON, err := CreatePreKeyStore(responderBlob, 0)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	published, err := PublishBundleJSON(storeJSON, responderBlob)
	if err != nil {
		t.Fatalf("PublishBundleJSON: %v", err)
	}

	var got publishBundleJSON
	if err := json.Unmarshal([]byte(published), &got); err != nil {
		t.Fatalf("the published bundle is not valid JSON: %v", err)
	}
	if len(got.OneTimePreKeys) != 0 {
		t.Fatalf("an empty pool published %d prekeys", len(got.OneTimePreKeys))
	}
	// An explicit empty array rather than JSON null: the relay's decoder must not have
	// to treat a missing field and an empty pool differently.
	if !strings.Contains(published, `"one_time_pre_keys":[]`) {
		t.Fatalf("an empty pool should publish as [], got: %s", published)
	}

	initiator, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	initiatorBlob, err := IdentityToJSON(initiator)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}
	session, err := EstablishSession(initiatorBlob, responder.SigningPublic, published)
	if err != nil {
		t.Fatalf("the degraded bundle was rejected: %v", err)
	}
	session.Close()
}

// TestPublishBundleJSONRejectsGarbage keeps a caller from publishing a bundle that
// could never work.
func TestPublishBundleJSONRejectsGarbage(t *testing.T) {
	if _, err := PublishBundleJSON("{not json", strings.Repeat("ab", 32)); err == nil {
		t.Fatal("a malformed prekey store was accepted")
	}
	if _, err := PublishBundleJSON("{}", strings.Repeat("ab", 32)); err == nil {
		t.Fatal("an empty prekey store was accepted")
	}
}

// TestBothPeersCanComputeTheSafetyNumber is the property that makes the out-of-band
// comparison mean anything: both users must be able to produce the same 60 digits from
// what their own device knows. If only the initiator could, the responder would be
// asked to confirm a number it cannot check.
func TestBothPeersCanComputeTheSafetyNumber(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)

	initiatorID, err := IdentityFromJSON(initiatorBlob)
	if err != nil {
		t.Fatalf("IdentityFromJSON: %v", err)
	}
	responderID, err := IdentityFromJSON(responderBlob)
	if err != nil {
		t.Fatalf("IdentityFromJSON: %v", err)
	}

	storeJSON, err := CreatePreKeyStore(responderBlob, 3)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	wireBundle, responderIdentity := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	initiator, err := EstablishSession(initiatorBlob, responderIdentity, wireBundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	defer initiator.Close()

	responder, err := AcceptSession(responderBlob, storeJSON, initiator.InitMessage())
	if err != nil {
		t.Fatalf("AcceptSession: %v", err)
	}
	defer responder.Close()

	// The initiator learned the responder's identity from the bundle it fetched; the
	// responder learned the initiator's from the handshake initiation.
	if got := initiator.PeerIdentity(); got != responderID.SigningPublic {
		t.Fatalf("initiator sees peer %s, want the responder's %s", got, responderID.SigningPublic)
	}
	if got := responder.PeerIdentity(); got != initiatorID.SigningPublic {
		t.Fatalf("responder sees peer %s, want the initiator's %s", got, initiatorID.SigningPublic)
	}

	fromInitiator, err := SafetyNumber(initiatorID.SigningPublic, initiator.PeerIdentity())
	if err != nil {
		t.Fatalf("SafetyNumber on the initiator's side: %v", err)
	}
	fromResponder, err := SafetyNumber(responderID.SigningPublic, responder.PeerIdentity())
	if err != nil {
		t.Fatalf("SafetyNumber on the responder's side: %v", err)
	}

	if fromInitiator != fromResponder {
		t.Fatalf("the two users would compare different numbers:\n  initiator: %s\n  responder: %s",
			fromInitiator, fromResponder)
	}
	// The number is formatted into groups for reading aloud, so count digits rather
	// than characters.
	digits := 0
	for _, r := range fromInitiator {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits != 60 {
		t.Fatalf("the safety number has %d digits, want 60", digits)
	}
}

// TestPeerIdentitySurvivesASnapshot keeps a restart from silently disabling
// verification: the restored session still knows who it is talking to, and is still the
// same session.
func TestPeerIdentitySurvivesASnapshot(t *testing.T) {
	initiator, responder := newBoundPair(t)
	defer initiator.Close()
	defer responder.Close()

	want := responder.PeerIdentity()
	if want == "" {
		t.Fatal("the responder learned no peer identity")
	}

	blob, err := responder.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	responder.Close()

	restored, err := RestoreSession(blob)
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	defer restored.Close()

	if got := restored.PeerIdentity(); got != want {
		t.Fatalf("the restored session sees peer %s, want %s", got, want)
	}

	wire, err := initiator.Encrypt(testToken, []byte("after the restart"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := restored.Decrypt(wire)
	if err != nil {
		t.Fatalf("the restored session could not decrypt: %v", err)
	}
	if string(plain) != "after the restart" {
		t.Fatalf("decrypted %q", plain)
	}
}

// TestHexKeyWhereAnIdentityBlobBelongsIsRejectedClearly pins the guard added because of a
// real bug that survived several builds.
//
// The exported identity-taking functions used to name their parameter `identityHex` while
// passing it to a JSON parser. The first working client believed the name, passed the
// 64-character public key, and every publish failed with
//
//	scs1: parsing identity: invalid character 'a' looking for beginning of value
//
// — an error naming neither the function nor the mistake. Because the client also
// overwrote its own status line with that error, the symptom the user saw was on the OTHER
// device: "no bundle published for that identity", which looks like a network fault on
// someone else's phone.
//
// Both are strings, so no type checker can catch this. What can catch it is a message that
// says what to pass instead, which is what this test requires of every entry point.
func TestHexKeyWhereAnIdentityBlobBelongsIsRejectedClearly(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	blob, err := IdentityToJSON(identity)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}
	storeJSON, err := CreatePreKeyStore(blob, 2)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}

	calls := map[string]func() error{
		"CreatePreKeyStore": func() error {
			_, err := CreatePreKeyStore(identity.SigningPublic, 2)
			return err
		},
		"PublishBundle": func() error {
			_, err := PublishBundle(storeJSON, identity.SigningPublic, 0)
			return err
		},
		"PublishBundleJSON": func() error {
			_, err := PublishBundleJSON(storeJSON, identity.SigningPublic)
			return err
		},
		"EstablishSession": func() error {
			_, err := EstablishSession(identity.SigningPublic, identity.SigningPublic, "{}")
			return err
		},
		"AcceptSession": func() error {
			_, err := AcceptSession(identity.SigningPublic, storeJSON, make([]byte, 138))
			return err
		},
	}

	for name, call := range calls {
		err := call()
		if err == nil {
			t.Errorf("%s accepted a hex public key where an identity blob belongs", name)
			continue
		}
		if !strings.Contains(err.Error(), "identity JSON blob") {
			t.Errorf("%s returned %q, which does not tell the caller what to pass instead",
				name, err)
		}
	}

	// The guard must not cost the valid path anything.
	if _, err := PublishBundleJSON(storeJSON, blob); err != nil {
		t.Fatalf("the guard rejected a valid identity blob: %v", err)
	}
}

// TestMailboxTokenIsPinned pins the interim mailbox derivation.
//
// The golden value matters more than it looks. Both ends compute this independently —
// the sender to address the envelope, the receiver to subscribe — and a drift between
// them does not fail loudly, it makes handshakes silently never arrive. Changing the
// label or the truncation must therefore be a deliberate, visible edit to this test.
func TestMailboxTokenIsPinned(t *testing.T) {
	const zeroIdentity = "0000000000000000000000000000000000000000000000000000000000000000"

	token, err := MailboxToken(zeroIdentity)
	if err != nil {
		t.Fatalf("MailboxToken: %v", err)
	}
	if token != "8bb3aeca6bda8a03e2962c4412ceef48" {
		t.Fatalf("mailbox token for the all-zero identity is %s, want the pinned "+
			"8bb3aeca6bda8a03e2962c4412ceef48; changing the derivation breaks "+
			"delivery for every existing client", token)
	}
	if len(token) != MailboxTokenSize*2 {
		t.Fatalf("token is %d hex characters, want %d", len(token), MailboxTokenSize*2)
	}

	// The relay keys its router on protocol.TokenSize, so a mismatch here would put
	// every envelope in the wrong bucket.
	if MailboxTokenSize != protocol.TokenSize {
		t.Fatalf("MailboxTokenSize is %d but protocol.TokenSize is %d",
			MailboxTokenSize, protocol.TokenSize)
	}
}

// TestMailboxTokenIsStableAndIdentityBound checks the two properties callers rely on.
func TestMailboxTokenIsStableAndIdentityBound(t *testing.T) {
	a, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	b, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	tokenA, err := MailboxToken(a.SigningPublic)
	if err != nil {
		t.Fatalf("MailboxToken: %v", err)
	}
	again, err := MailboxToken(a.SigningPublic)
	if err != nil {
		t.Fatalf("MailboxToken: %v", err)
	}
	if tokenA != again {
		t.Fatal("the same identity produced two different mailboxes")
	}

	// Uppercase hex must not change the answer: the identity crosses the binding in
	// whatever case the caller happened to hold.
	upper, err := MailboxToken(strings.ToUpper(a.SigningPublic))
	if err != nil {
		t.Fatalf("MailboxToken on uppercase hex: %v", err)
	}
	if upper != tokenA {
		t.Fatal("uppercase and lowercase hex produced different mailboxes")
	}

	tokenB, err := MailboxToken(b.SigningPublic)
	if err != nil {
		t.Fatalf("MailboxToken: %v", err)
	}
	if tokenA == tokenB {
		t.Fatal("two distinct identities collided on one mailbox")
	}
}

// TestMailboxTokenRejectsBadInput checks the boundary rather than trusting it.
func TestMailboxTokenRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"not hex":            "zz" + strings.Repeat("00", 31),
		"too short":          strings.Repeat("ab", 16),
		"too long":           strings.Repeat("ab", 33),
		"odd length":         strings.Repeat("a", 63),
		"leading whitespace": "  " + strings.Repeat("ab", 32),
		"inner whitespace":   strings.Repeat("ab", 31) + " " + "cd",
	}

	for name, input := range cases {
		if _, err := MailboxToken(input); err == nil {
			t.Errorf("%s: MailboxToken accepted %q", name, input)
		}
	}
}
