package mobile

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/schat/schat/protocol"
)

// These tests exercise the binding layer without gomobile. Everything here is
// ordinary Go: the gomobile build only wraps these functions, so if the logic is
// right here it is right in the .aar. That keeps the expensive cross-compilation
// step from being the only place a bug can be caught.

func TestGenerateIdentityRoundTripsThroughJSON(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	for name, v := range map[string]string{
		"signing public":    id.SigningPublic,
		"agreement public":  id.AgreementPublic,
		"signing private":   id.SigningPrivate,
		"agreement private": id.AgreementPrivate,
	} {
		if _, err := hex.DecodeString(v); err != nil {
			t.Fatalf("%s is not valid hex: %v", name, err)
		}
	}

	blob, err := IdentityToJSON(id)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}

	back, err := IdentityFromJSON(blob)
	if err != nil {
		t.Fatalf("IdentityFromJSON: %v", err)
	}
	if *back != *id {
		t.Fatal("an identity did not survive the JSON round trip")
	}
}

func TestIdentityFromJSONRejectsIncompleteInput(t *testing.T) {
	if _, err := IdentityFromJSON(`{}`); err == nil {
		t.Error("expected an error for an identity with no public keys")
	}
	if _, err := IdentityFromJSON(`not json`); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestCreatePreKeyStoreAndPublishBundle(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	blob, err := IdentityToJSON(id)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}

	storeJSON, err := CreatePreKeyStore(blob, 5)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	if !strings.Contains(storeJSON, "signed_pre_key_private") {
		t.Fatal("the store blob does not look like the documented shape")
	}

	// With a one-time prekey attached.
	bundle, err := PublishBundle(storeJSON, blob, 2)
	if err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}
	if bundle.OneTimePreKey == "" || bundle.OneTimePreKeyID != 2 {
		t.Fatalf("bundle did not carry the requested one-time prekey: %+v", bundle)
	}

	// The published signature must verify against the published identity, or no
	// peer could ever start a session.
	signPub, _ := hex.DecodeString(bundle.IdentitySigning)
	spk, _ := hex.DecodeString(bundle.SignedPreKey)
	sig, _ := hex.DecodeString(bundle.SignedPreKeySignature)
	if err := protocol.Verify(signPub, spk, sig); err != nil {
		t.Fatalf("the published bundle signature does not verify: %v", err)
	}

	// Without a one-time prekey: a legitimate degraded mode, not an error.
	degraded, err := PublishBundle(storeJSON, blob, 0)
	if err != nil {
		t.Fatalf("PublishBundle without a one-time prekey: %v", err)
	}
	if degraded.OneTimePreKey != "" {
		t.Fatal("a bundle without a one-time prekey still carried one")
	}
}

// TestPreKeyStoreSurvivesPersistence is the property the client actually depends on:
// the pool is written into the vault and read back, and a handshake works afterwards.
func TestPreKeyStoreSurvivesPersistence(t *testing.T) {
	initiator, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	responder, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	initiatorBlob, _ := IdentityToJSON(initiator)
	responderBlob, _ := IdentityToJSON(responder)

	storeJSON, err := CreatePreKeyStore(responderBlob, 3)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	bundle, err := PublishBundle(storeJSON, responderBlob, 1)
	if err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	// Rebuild the responder's store purely from the persisted blob, as a client
	// would after a restart.
	rebuilt, err := preKeyStoreFromBinding(storeJSON)
	if err != nil {
		t.Fatalf("preKeyStoreFromBinding: %v", err)
	}
	if len(rebuilt.OneTimePreKeyIDs()) != 3 {
		t.Fatalf("the rebuilt store holds %d prekeys, want 3", len(rebuilt.OneTimePreKeyIDs()))
	}

	// And a real handshake must work through the reconstructed material.
	idA, err := identityFromBinding(initiatorBlob)
	if err != nil {
		t.Fatalf("parsing the initiator identity: %v", err)
	}
	idB, err := identityFromBinding(responderBlob)
	if err != nil {
		t.Fatalf("parsing the responder identity: %v", err)
	}

	pb := protocol.PreKeyBundle{
		IdentitySigning:       mustHex(t, bundle.IdentitySigning),
		IdentityAgreement:     mustHex(t, bundle.IdentityAgreement),
		SignedPreKey:          mustHex(t, bundle.SignedPreKey),
		SignedPreKeyID:        uint32(bundle.SignedPreKeyID),
		SignedPreKeySignature: mustHex(t, bundle.SignedPreKeySignature),
		OneTimePreKey:         mustHex(t, bundle.OneTimePreKey),
		OneTimePreKeyID:       uint32(bundle.OneTimePreKeyID),
	}

	sessionA, init, err := protocol.EstablishSession(idA, pb)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	defer sessionA.Close()

	sessionB, err := protocol.AcceptSession(idB, rebuilt, init)
	if err != nil {
		t.Fatalf("AcceptSession with a reconstructed store: %v", err)
	}
	defer sessionB.Close()

	env, err := sessionA.EncryptMessage([]byte("through the binding layer"), protocol.ProfileText)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := sessionB.DecryptMessage(env)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(got) != "through the binding layer" {
		t.Fatalf("got %q", got)
	}
}

func TestDeriveVaultKey(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if len(salt) != 64 {
		t.Fatalf("salt is %d hex characters, want 64", len(salt))
	}

	const deviceKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	key, err := DeriveVaultKey("correct horse battery staple", salt, deviceKey, VaultProfileLow)
	if err != nil {
		t.Fatalf("DeriveVaultKey: %v", err)
	}
	if len(key) != 128 {
		t.Fatalf("vault key is %d hex characters, want 128 (64 bytes)", len(key))
	}

	// Deterministic.
	again, err := DeriveVaultKey("correct horse battery staple", salt, deviceKey, VaultProfileLow)
	if err != nil {
		t.Fatalf("DeriveVaultKey (repeat): %v", err)
	}
	if key != again {
		t.Fatal("vault key derivation is not deterministic")
	}

	// The passphrase matters.
	other, err := DeriveVaultKey("wrong passphrase", salt, deviceKey, VaultProfileLow)
	if err != nil {
		t.Fatalf("DeriveVaultKey (other passphrase): %v", err)
	}
	if key == other {
		t.Fatal("the passphrase did not affect the vault key")
	}

	// The device key matters: an attacker with the database and the passphrase but
	// not the phone must still fail.
	const otherDeviceKey = "abababababababababababababababababababababababababababababababab"
	otherDevice, err := DeriveVaultKey("correct horse battery staple", salt, otherDeviceKey, VaultProfileLow)
	if err != nil {
		t.Fatalf("DeriveVaultKey (other device): %v", err)
	}
	if key == otherDevice {
		t.Fatal("the device key did not affect the vault key")
	}

	// The salt matters.
	otherSalt, _ := NewSalt()
	otherSalted, err := DeriveVaultKey("correct horse battery staple", otherSalt, deviceKey, VaultProfileLow)
	if err != nil {
		t.Fatalf("DeriveVaultKey (other salt): %v", err)
	}
	if key == otherSalted {
		t.Fatal("the salt did not affect the vault key")
	}
}

func TestDeriveVaultKeyRejectsBadInput(t *testing.T) {
	const deviceKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	salt, _ := NewSalt()

	if _, err := DeriveVaultKey("pw", "not hex", deviceKey, VaultProfileLow); err == nil {
		t.Error("expected an error for a non-hex salt")
	}
	if _, err := DeriveVaultKey("pw", salt, "not hex", VaultProfileLow); err == nil {
		t.Error("expected an error for a non-hex device key")
	}
	if _, err := DeriveVaultKey("pw", salt, "aabb", VaultProfileLow); err == nil {
		t.Error("expected an error for a device key of the wrong length")
	}
	if _, err := DeriveVaultKey("pw", salt, deviceKey, "paranoid"); err == nil {
		t.Error("expected an error for an unknown profile")
	}
	if _, err := DeriveVaultKey("", salt, deviceKey, VaultProfileLow); err == nil {
		t.Error("expected an error for an empty passphrase")
	}
}

func TestVaultProfilesWiden(t *testing.T) {
	// A guard against anyone quietly making the low profile cheaper.
	low, err := argon2Params(VaultProfileLow)
	if err != nil {
		t.Fatalf("argon2Params(low): %v", err)
	}
	if low.Memory < 32*1024 {
		t.Fatalf("the low vault profile dropped below 32 MiB (%d KiB)", low.Memory)
	}
	balanced, _ := argon2Params(VaultProfileBalanced)
	high, _ := argon2Params(VaultProfileHigh)

	if balanced.Memory <= low.Memory {
		t.Error("balanced must cost more memory than low")
	}
	if high.Memory <= balanced.Memory {
		t.Error("high must cost more memory than balanced")
	}
}

func TestDeliveryTokens(t *testing.T) {
	routeKey, err := NewRouteKey()
	if err != nil {
		t.Fatalf("NewRouteKey: %v", err)
	}
	if len(routeKey) != 64 {
		t.Fatalf("route key is %d hex characters, want 64", len(routeKey))
	}

	tokens, err := DeliveryTokens(routeKey, 20000, 8)
	if err != nil {
		t.Fatalf("DeliveryTokens: %v", err)
	}
	if len(tokens) != 8 {
		t.Fatalf("got %d tokens, want 8", len(tokens))
	}

	seen := map[string]bool{}
	for i, tk := range tokens {
		if len(tk) != 32 {
			t.Fatalf("token %d is %d hex characters, want 32", i, len(tk))
		}
		if _, err := hex.DecodeString(tk); err != nil {
			t.Fatalf("token %d is not valid hex: %v", i, err)
		}
		if seen[tk] {
			t.Fatalf("token %d duplicates an earlier one", i)
		}
		seen[tk] = true
	}

	// Deterministic: the recipient computes the same tokens without communication.
	again, err := DeliveryTokens(routeKey, 20000, 8)
	if err != nil {
		t.Fatalf("DeliveryTokens (repeat): %v", err)
	}
	for i := range tokens {
		if tokens[i] != again[i] {
			t.Fatal("token derivation is not deterministic")
		}
	}

	// A new epoch must produce a completely different set, or yesterday's tokens
	// would still be valid.
	nextDay, err := DeliveryTokens(routeKey, 20001, 8)
	if err != nil {
		t.Fatalf("DeliveryTokens (next epoch): %v", err)
	}
	for i := range tokens {
		if tokens[i] == nextDay[i] {
			t.Fatalf("token %d did not rotate across epochs", i)
		}
	}
}

func TestDeliveryTokensRejectsBadInput(t *testing.T) {
	routeKey, _ := NewRouteKey()

	if _, err := DeliveryTokens("not hex", 1, 4); err == nil {
		t.Error("expected an error for a non-hex route key")
	}
	if _, err := DeliveryTokens(routeKey, 1, 0); err == nil {
		t.Error("expected an error for a zero token count")
	}
	if _, err := DeliveryTokens(routeKey, 1, 100000); err == nil {
		t.Error("expected an error for an unbounded token count")
	}
	if _, err := DeliveryTokens(routeKey, -1, 4); err == nil {
		t.Error("expected an error for a negative epoch")
	}
}

// TestSafetyNumberIsSymmetricAndSixtyDigits is the usability-critical property: two
// users comparing codes must see identical digits.
func TestSafetyNumberIsSymmetricAndSixtyDigits(t *testing.T) {
	a := "aa" + strings.Repeat("01", 31)
	b := "bb" + strings.Repeat("02", 31)

	ab, err := SafetyNumber(a, b)
	if err != nil {
		t.Fatalf("SafetyNumber: %v", err)
	}
	ba, err := SafetyNumber(b, a)
	if err != nil {
		t.Fatalf("SafetyNumber (reversed): %v", err)
	}
	if ab != ba {
		t.Fatalf("the two users would see different codes:\n  %s\n  %s", ab, ba)
	}

	digits := strings.NewReplacer(" ", "").Replace(ab)
	if len(digits) != 60 {
		t.Fatalf("the code has %d digits, want 60: %q", len(digits), ab)
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			t.Fatalf("the code contains a non-digit: %q", ab)
		}
	}

	// Every group must carry entropy. A naive 8-byte-chunk implementation over a
	// 32-byte digest leaves eight of the twelve groups as "00000", silently cutting
	// the code to 20 meaningful digits.
	if strings.Count(ab, "00000") > 1 {
		t.Fatalf("too many groups are all-zero, which suggests the digest is being sliced rather than expanded: %q", ab)
	}

	// A different peer must produce a different code.
	other, err := SafetyNumber(a, "cc"+strings.Repeat("03", 31))
	if err != nil {
		t.Fatalf("SafetyNumber (other peer): %v", err)
	}
	if other == ab {
		t.Fatal("the code does not depend on the peer identity")
	}

	if _, err := SafetyNumber("nope", b); err == nil {
		t.Error("expected an error for a non-hex identity")
	}
}

func TestCurrentEpochMatchesTheProtocol(t *testing.T) {
	// The client must not reimplement the 24-hour bucket boundary, so this asserts
	// the binding simply forwards it.
	cases := []struct {
		unix int64
		want int64
	}{
		{0, 0},
		{86399, 0},
		{86400, 1},
		{172800, 2},
	}
	for _, c := range cases {
		if got := CurrentEpoch(c.unix); got != c.want {
			t.Errorf("CurrentEpoch(%d) = %d, want %d", c.unix, got, c.want)
		}
	}
}

func TestVersionStrings(t *testing.T) {
	if Version() == "" {
		t.Error("Version returned an empty string")
	}
	if !strings.Contains(ProtocolName(), "SCS-1") {
		t.Errorf("ProtocolName %q does not mention SCS-1", ProtocolName())
	}
	if !strings.Contains(ProtocolName(), "MLS") {
		t.Errorf("ProtocolName %q does not mention the group protocol", ProtocolName())
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return out
}
