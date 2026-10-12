// Package mobile is the gomobile binding surface for the SCS-1 protocol core.
//
// # Why this package exists
//
// The Android client must run exactly the same cryptography as the Go tests, the
// Go relay's envelope handling and any future desktop client. Reimplementing SCS-1
// in Kotlin would double the code that has to be correct and guarantee that the two
// copies eventually diverge — and a divergent protocol implementation is not a
// portability problem, it is a silent authentication failure waiting to happen.
//
// So the protocol lives in Go, and gomobile generates the Java/Kotlin bindings.
//
// # Constraints this package works under
//
// gomobile supports a narrow type vocabulary: string, []byte, bool, numeric types,
// error, exported structs of those, and slices of them. It does not support maps,
// generics, interfaces with methods, or multiple return values. Everything awkward
// is therefore expressed as JSON in a string, which has the useful side effect of
// making the wire shape between Go and Kotlin explicit and testable.
//
// # What lives here, and what does not
//
// This is step 4's surface: identity creation, prekey publication, vault key
// derivation, delivery tokens and the safety number — everything the client needs
// to onboard, protect its local database and connect to a relay.
//
// Session establishment and the ratchet are added in step 5. They are not here yet,
// and no stub is provided for them: a stub that returns empty values would be worse
// than a compile error, because it would let a half-built client appear to work.
package mobile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/schat/schat/protocol"
)

// Version returns the protocol library version.
func Version() string { return protocol.LibraryVersion }

// ProtocolName describes the protocols in use, for display in the client.
func ProtocolName() string {
	return "SCS-1/v1 pairwise, " + protocol.GroupProtocolMLS + " groups"
}

// Identity is a long-term identity, carried across the binding as hex strings.
//
// # Handling of the private halves
//
// The private keys are handed to Kotlin so that the client can store them inside
// its encrypted vault, which is where they have to live: the vault key depends on
// both the user's passphrase and a hardware-bound Keystore key, and only the Kotlin
// side can reach the Keystore. Keeping them inside Go would leave no way to persist
// them across a restart.
//
// The consequence is that the private material briefly exists as a managed string in
// the Kotlin heap, where the garbage collector — not this package — decides when it
// is released. That is a real, documented limitation: see SCHAT.md section 4.9. The
// client mitigates it by writing the value straight into the vault and dropping the
// reference, and by never logging it.
type Identity struct {
	// SigningPublic is the hex Ed25519 public key.
	SigningPublic string

	// AgreementPublic is the hex X25519 public key.
	AgreementPublic string

	// SigningPrivate is the hex Ed25519 private key.
	SigningPrivate string

	// AgreementPrivate is the hex X25519 private key.
	AgreementPrivate string
}

// GenerateIdentity creates a fresh long-term identity.
func GenerateIdentity() (*Identity, error) {
	kp, err := protocol.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	return &Identity{
		SigningPublic:    hex.EncodeToString(kp.SigningPublic),
		AgreementPublic:  hex.EncodeToString(kp.AgreementPublic),
		SigningPrivate:   hex.EncodeToString(kp.SigningPrivate),
		AgreementPrivate: hex.EncodeToString(kp.AgreementPrivate),
	}, nil
}

// PreKeyBundle is the publishable material other peers fetch to start a session.
type PreKeyBundle struct {
	// IdentitySigning is the hex Ed25519 public key.
	IdentitySigning string

	// IdentityAgreement is the hex X25519 public key.
	IdentityAgreement string

	// SignedPreKey is the hex X25519 signed prekey.
	SignedPreKey string

	// SignedPreKeyID identifies which signed prekey this is.
	SignedPreKeyID int64

	// SignedPreKeySignature is the hex Ed25519 signature over SignedPreKey.
	SignedPreKeySignature string

	// OneTimePreKey is the hex X25519 one-time prekey, or empty.
	OneTimePreKey string

	// OneTimePreKeyID identifies which one-time prekey was attached.
	OneTimePreKeyID int64
}

// preKeyStoreJSON is how a PreKeyStore crosses the binding.
//
// gomobile cannot carry a map, and the one-time prekey pool is a map keyed by id,
// so it is serialised as parallel slices.
type preKeyStoreJSON struct {
	SignedPreKeyID        int64    `json:"signed_pre_key_id"`
	SignedPreKeyPrivate   string   `json:"signed_pre_key_private"`
	SignedPreKeyPublic    string   `json:"signed_pre_key_public"`
	SignedPreKeySignature string   `json:"signed_pre_key_signature"`
	OneTimeIDs            []int64  `json:"one_time_prekey_ids"`
	OneTimePrivates       []string `json:"one_time_prekey_privates"`
	OneTimePublics        []string `json:"one_time_prekey_publics"`
}

// CreatePreKeyStore generates prekey material for an identity and returns it as a
// JSON blob for the client to store inside its vault.
//
// identityJSON is the blob from IdentityToJSON — NOT the hex public key, despite what the
// parameter was called before this was fixed.
//
// count is the size of the one-time prekey pool. A pool of 100 is the documented
// default; zero is legal but gives up forward secrecy for the session's first
// message.
func CreatePreKeyStore(identityJSON string, count int) (string, error) {
	id, err := identityFromBinding(identityJSON)
	if err != nil {
		return "", err
	}
	defer id.Zero()

	store, err := protocol.NewPreKeyStore(id, count)
	if err != nil {
		return "", err
	}

	out := preKeyStoreJSON{
		SignedPreKeyID:        int64(store.SignedPreKeyID),
		SignedPreKeyPrivate:   hex.EncodeToString(store.SignedPreKeyPrivate),
		SignedPreKeyPublic:    hex.EncodeToString(store.SignedPreKeyPublic),
		SignedPreKeySignature: hex.EncodeToString(store.SignedPreKeySignature),
	}

	for _, id := range store.OneTimePreKeyIDs() {
		pub, priv, ok := store.ExportOneTimePreKey(id)
		if !ok {
			continue
		}
		out.OneTimeIDs = append(out.OneTimeIDs, int64(id))
		out.OneTimePrivates = append(out.OneTimePrivates, hex.EncodeToString(priv))
		out.OneTimePublics = append(out.OneTimePublics, hex.EncodeToString(pub))
	}

	raw, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// PublishBundle builds the PreKeyBundle to hand to the relay's key directory.
//
// identityJSON is the blob from IdentityToJSON — NOT the hex public key.
//
// Pass oneTimePreKeyID = 0 to publish without a one-time prekey.
func PublishBundle(storeJSON string, identityJSON string, oneTimePreKeyID int64) (*PreKeyBundle, error) {
	id, err := identityFromBinding(identityJSON)
	if err != nil {
		return nil, err
	}
	defer id.Zero()

	store, err := preKeyStoreFromBinding(storeJSON)
	if err != nil {
		return nil, err
	}

	bundle, err := store.Bundle(id, uint32(oneTimePreKeyID))
	if err != nil {
		return nil, err
	}

	return &PreKeyBundle{
		IdentitySigning:       hex.EncodeToString(bundle.IdentitySigning),
		IdentityAgreement:     hex.EncodeToString(bundle.IdentityAgreement),
		SignedPreKey:          hex.EncodeToString(bundle.SignedPreKey),
		SignedPreKeyID:        int64(bundle.SignedPreKeyID),
		SignedPreKeySignature: hex.EncodeToString(bundle.SignedPreKeySignature),
		OneTimePreKey:         hex.EncodeToString(bundle.OneTimePreKey),
		OneTimePreKeyID:       int64(bundle.OneTimePreKeyID),
	}, nil
}

// publishBundleJSON is the shape the relay's prekey directory accepts.
//
// It mirrors server/internal/directory.Bundle field for field, and is declared here
// rather than imported so that the client binding keeps no dependency on server code.
// A mismatch between the two would be silent — the directory would reject the publish
// with a 400 and the user would simply never be reachable — so the test suite checks
// that this output round-trips into EstablishSession.
type publishBundleJSON struct {

	// KeyPackage carries the publisher's MLS KeyPackage, hex-encoded, so that another
	// member can add it to a group without an exchange out of band. It is optional: a
	// client that only does one-to-one sessions never publishes one.
	//
	// The server checks that it is hex and within a size bound, and parses nothing
	// further — the relay must not understand MLS.
	KeyPackage            string              `json:"key_package,omitempty"`
	IdentitySigning       string              `json:"identity_signing"`
	IdentityAgreement     string              `json:"identity_agreement"`
	SignedPreKey          string              `json:"signed_pre_key"`
	SignedPreKeyID        int64               `json:"signed_pre_key_id"`
	SignedPreKeySignature string              `json:"signed_pre_key_signature"`
	OneTimePreKeys        []publishPreKeyJSON `json:"one_time_pre_keys"`
}

// publishPreKeyJSON is one one-time prekey in a published bundle.
type publishPreKeyJSON struct {
	ID     int64  `json:"id"`
	Public string `json:"public"`
}

// PublishBundleJSON renders the whole bundle to hand to the relay's key directory.
//
// # Why this exists next to PublishBundle
//
// PublishBundle attaches a single one-time prekey, which is the wrong shape for a
// directory that REPLACES an identity's entry on every publish and consumes one prekey
// per fetch. Publishing one prekey at a time would leave a pool of exactly one: the
// first peer to start a session would drain it, and every peer after that would
// silently fall back to the degraded mode with no forward secrecy for its first
// message. That failure is invisible to both sides, which is what makes it worth a
// separate function rather than a warning.
//
// Using PublishBundle in a loop would be worse still, not better: each call replaces
// the previous entry, so the pool would hold only the last prekey published.
//
// identityJSON is the blob from IdentityToJSON — NOT the hex public key. This parameter
// was called identityHex when it was written, and a client that believed the name passed
// the public key, which made every publish fail with an unhelpful JSON parse error.
func PublishBundleJSON(storeJSON string, identityJSON string) (string, error) {
	return PublishBundleJSONWithKeyPackage(storeJSON, identityJSON, "")
}

// PublishBundleJSONWithKeyPackage publishes the bundle together with an MLS KeyPackage.
//
// The KeyPackage goes INSIDE the bundle rather than being published separately, because the
// directory stores one opaque record per identity and the server understands none of it. The
// alternative — a second endpoint — would mean a second place for the same identity to be
// overwritten, and the publishing is unauthenticated by design (see the directory package).
//
// The field is omitted entirely when keyPackageHex is empty, so a client that has no group
// support yet publishes exactly what it published before.
func PublishBundleJSONWithKeyPackage(storeJSON string, identityJSON string, keyPackageHex string) (string, error) {
	id, err := identityFromBinding(identityJSON)
	if err != nil {
		return "", err
	}
	defer id.Zero()

	store, err := preKeyStoreFromBinding(storeJSON)
	if err != nil {
		return "", err
	}
	defer store.Zero()

	// id 0 asks for the bundle WITHOUT attaching any one-time prekey; the pool is
	// enumerated separately below so that all of it can be published.
	base, err := store.Bundle(id, 0)
	if err != nil {
		return "", err
	}

	out := publishBundleJSON{
		IdentitySigning:       hex.EncodeToString(base.IdentitySigning),
		IdentityAgreement:     hex.EncodeToString(base.IdentityAgreement),
		SignedPreKey:          hex.EncodeToString(base.SignedPreKey),
		SignedPreKeyID:        int64(base.SignedPreKeyID),
		SignedPreKeySignature: hex.EncodeToString(base.SignedPreKeySignature),
		OneTimePreKeys:        make([]publishPreKeyJSON, 0, len(store.OneTimePreKeyIDs())),
	}

	for _, kid := range store.OneTimePreKeyIDs() {
		public, _, ok := store.ExportOneTimePreKey(kid)
		if !ok {
			// A prekey that cannot be exported cannot be published. Skipping it is
			// correct: publishing a zero value would be a public key nobody holds
			// the private half of, and every session started from it would fail.
			continue
		}
		out.OneTimePreKeys = append(out.OneTimePreKeys, publishPreKeyJSON{
			ID:     int64(kid),
			Public: hex.EncodeToString(public),
		})
	}

	// A KeyPackage that is not hex would be rejected by the server; refusing it here says
	// which side made the mistake, and it is not a mistake a user can fix.
	if keyPackageHex != "" {
		if _, err := hex.DecodeString(keyPackageHex); err != nil {
			return "", fmt.Errorf("schat: the KeyPackage is not hex: %w", err)
		}
		out.KeyPackage = keyPackageHex
	}

	raw, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// VaultProfiles are the Argon2id cost profiles from SCHAT.md section 4.8.
const (
	// VaultProfileLow targets entry-level devices: 32 MiB, roughly 0.25 s.
	VaultProfileLow = "low"

	// VaultProfileBalanced is the default: 64 MiB, roughly 0.5 s.
	VaultProfileBalanced = "balanced"

	// VaultProfileHigh targets flagship devices: 256 MiB, roughly 2 s.
	VaultProfileHigh = "high"
)

// NewSalt returns 32 fresh random bytes as hex, for use as a vault salt.
func NewSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("scs1: generating salt: %w", err)
	}
	return hex.EncodeToString(salt), nil
}

// DeriveVaultKey derives the 64-byte key that protects the local database:
// the first 32 bytes are the cipher key, the last 32 the MAC key.
//
// # The two factors
//
// passphrase is the user's. deviceKey must come from the Android Keystore — ideally
// StrongBox — and must be non-exportable. Requiring both is what makes an attacker
// who exfiltrates the database file and guesses the passphrase still unable to read
// it without the physical device (SCHAT.md section 4.8).
//
// The profile selects the Argon2id cost. Memory is the parameter that matters:
// lowering it to save RAM multiplies a GPU attacker's throughput, so the low profile
// is still 32 MiB.
func DeriveVaultKey(passphrase string, saltHex string, deviceKeyHex string, profile string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("scs1: vault salt is not valid hex: %w", err)
	}
	deviceKey, err := hex.DecodeString(deviceKeyHex)
	if err != nil {
		return "", fmt.Errorf("scs1: device key is not valid hex: %w", err)
	}

	params, err := argon2Params(profile)
	if err != nil {
		return "", err
	}

	material, err := protocol.DeriveVaultMaterial([]byte(passphrase), salt, params)
	if err != nil {
		return "", err
	}
	defer protocol.Zero(material)

	key, err := protocol.DeriveVaultKey(material, deviceKey, salt)
	if err != nil {
		return "", err
	}
	defer protocol.Zero(key)

	return hex.EncodeToString(key), nil
}

// DeliveryTokens derives count delivery tokens for one rotation epoch.
//
// The client hands a batch of these to each contact over an established session and
// then deposits envelopes into the token the other side chose. The relay learns only
// that some connection is depositing into a mailbox, never who owns it
// (SCHAT.md section 4.7).
func DeliveryTokens(routeKeyHex string, epoch int64, count int) ([]string, error) {
	routeKey, err := hex.DecodeString(routeKeyHex)
	if err != nil {
		return nil, fmt.Errorf("scs1: route key is not valid hex: %w", err)
	}
	if count <= 0 || count > protocol.TokenBatchSize*4 {
		return nil, fmt.Errorf("scs1: token count %d is out of range", count)
	}
	if epoch < 0 {
		return nil, fmt.Errorf("scs1: epoch must not be negative")
	}

	tokens := make([]string, 0, count)
	for i := 0; i < count; i++ {
		token, err := protocol.DeliveryToken(routeKey, uint64(epoch), uint32(i))
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, hex.EncodeToString(token[:]))
	}
	return tokens, nil
}

// CurrentEpoch returns the token rotation epoch for a Unix timestamp in seconds.
//
// It is exposed so that the client does not have to reimplement the 24-hour bucket
// boundary and get it subtly wrong.
func CurrentEpoch(unixSeconds int64) int64 {
	return int64(protocol.EpochFor(unixSeconds))
}

// NewRouteKey returns 32 fresh random bytes as hex, for use as a delivery route key.
func NewRouteKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("scs1: generating route key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// SafetyNumber returns the 60-digit identity verification code, rendered as twelve
// groups of five digits.
//
// Both users must see exactly the same digits or verification is impossible, which
// is why the rendering lives in the protocol package rather than being reinvented
// per platform.
func SafetyNumber(identityAHex string, identityBHex string) (string, error) {
	a, err := hex.DecodeString(identityAHex)
	if err != nil {
		return "", fmt.Errorf("scs1: identity A is not valid hex: %w", err)
	}
	b, err := hex.DecodeString(identityBHex)
	if err != nil {
		return "", fmt.Errorf("scs1: identity B is not valid hex: %w", err)
	}

	return protocol.SafetyDigits(a, b), nil
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

func argon2Params(profile string) (protocol.Argon2Params, error) {
	switch profile {
	case VaultProfileLow, "":
		return protocol.Argon2Low, nil
	case VaultProfileBalanced:
		return protocol.Argon2Balanced, nil
	case VaultProfileHigh:
		return protocol.Argon2High, nil
	default:
		return protocol.Argon2Params{}, fmt.Errorf("scs1: unknown vault profile %q", profile)
	}
}

// identityJSON is the shape identityFromBinding accepts: the same one GenerateIdentity
// returns, so a caller can round-trip an Identity through JSON.
type identityJSON struct {
	SigningPublic    string `json:"signing_public"`
	AgreementPublic  string `json:"agreement_public"`
	SigningPrivate   string `json:"signing_private"`
	AgreementPrivate string `json:"agreement_private"`
}

// IdentityToJSON renders an Identity as JSON for storage in the client's vault.
func IdentityToJSON(id *Identity) (string, error) {
	if id == nil {
		return "", fmt.Errorf("scs1: nil identity")
	}
	raw, err := json.Marshal(identityJSON{
		SigningPublic:    id.SigningPublic,
		AgreementPublic:  id.AgreementPublic,
		SigningPrivate:   id.SigningPrivate,
		AgreementPrivate: id.AgreementPrivate,
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// IdentityFromJSON parses the JSON produced by IdentityToJSON.
func IdentityFromJSON(blob string) (*Identity, error) {
	var parsed identityJSON
	if err := json.Unmarshal([]byte(blob), &parsed); err != nil {
		return nil, fmt.Errorf("scs1: parsing identity: %w", err)
	}
	if parsed.SigningPublic == "" || parsed.AgreementPublic == "" {
		return nil, fmt.Errorf("scs1: identity is missing its public keys")
	}
	return &Identity{
		SigningPublic:    parsed.SigningPublic,
		AgreementPublic:  parsed.AgreementPublic,
		SigningPrivate:   parsed.SigningPrivate,
		AgreementPrivate: parsed.AgreementPrivate,
	}, nil
}

// identityFromBinding parses the identity JSON blob produced by IdentityToJSON.
//
// # Why the guard below exists
//
// The parameter is a string, and so is a hex public key, so the compiler cannot tell them
// apart. Three exported functions used to name their parameter `identityHex` while passing
// it straight here — a name that is simply false, and one that a client trusted: the first
// working client passed the 64-character public key and got
//
//	scs1: parsing identity: invalid character 'a' looking for beginning of value
//
// which names neither the function nor the mistake, and which failed silently in the UI
// for several builds (the publish error was being overwritten by the connection status).
// The consequence was that no device could ever publish its prekeys, so every peer saw
// "no bundle published for that identity" and the whole fault looked like a network
// problem on the other phone.
//
// The check is here, at the single choke point all identity-taking functions share, rather
// than in each caller.
func identityFromBinding(blob string) (*protocol.IdentityKeyPair, error) {
	if !strings.HasPrefix(strings.TrimSpace(blob), "{") {
		return nil, fmt.Errorf(
			"scs1: expected the identity JSON blob from IdentityToJSON, got %s. "+
				"A hex public key cannot be used here: the private halves live in the blob",
			describeBlob(blob))
	}

	id, err := IdentityFromJSON(blob)
	if err != nil {
		return nil, err
	}
	signPriv, err := hex.DecodeString(id.SigningPrivate)
	if err != nil {
		return nil, fmt.Errorf("scs1: signing private key is not valid hex: %w", err)
	}
	signPub, err := hex.DecodeString(id.SigningPublic)
	if err != nil {
		return nil, fmt.Errorf("scs1: signing public key is not valid hex: %w", err)
	}
	agreePriv, err := hex.DecodeString(id.AgreementPrivate)
	if err != nil {
		return nil, fmt.Errorf("scs1: agreement private key is not valid hex: %w", err)
	}
	agreePub, err := hex.DecodeString(id.AgreementPublic)
	if err != nil {
		return nil, fmt.Errorf("scs1: agreement public key is not valid hex: %w", err)
	}

	return &protocol.IdentityKeyPair{
		SigningPrivate:   signPriv,
		SigningPublic:    signPub,
		AgreementPrivate: agreePriv,
		AgreementPublic:  agreePub,
	}, nil
}

// describeBlob names what a caller passed where an identity blob was expected, so the
// error can say "what looks like a 64-character hex public key" instead of quoting a
// fragment of the value and leaving the reader to work it out.
func describeBlob(value string) string {
	if value == "" {
		return "an empty string"
	}

	preview := value
	if len(preview) > 24 {
		preview = preview[:24] + "..."
	}

	hexish := true
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			hexish = false
		}
		if !hexish {
			break
		}
	}

	if hexish && len(value) == 64 {
		return fmt.Sprintf("what looks like a 64-character hex public key (%s)", preview)
	}
	return fmt.Sprintf("%d characters beginning %q", len(value), preview)
}

func preKeyStoreFromBinding(blob string) (*protocol.PreKeyStore, error) {
	var parsed preKeyStoreJSON
	if err := json.Unmarshal([]byte(blob), &parsed); err != nil {
		return nil, fmt.Errorf("scs1: parsing prekey store: %w", err)
	}

	spkPriv, err := hex.DecodeString(parsed.SignedPreKeyPrivate)
	if err != nil {
		return nil, fmt.Errorf("scs1: signed prekey private is not valid hex: %w", err)
	}
	spkPub, err := hex.DecodeString(parsed.SignedPreKeyPublic)
	if err != nil {
		return nil, fmt.Errorf("scs1: signed prekey public is not valid hex: %w", err)
	}
	sig, err := hex.DecodeString(parsed.SignedPreKeySignature)
	if err != nil {
		return nil, fmt.Errorf("scs1: signed prekey signature is not valid hex: %w", err)
	}

	privates := make(map[uint32][]byte, len(parsed.OneTimeIDs))
	publics := make(map[uint32][]byte, len(parsed.OneTimeIDs))

	for i, id := range parsed.OneTimeIDs {
		if i >= len(parsed.OneTimePrivates) || i >= len(parsed.OneTimePublics) {
			return nil, fmt.Errorf("scs1: prekey store has mismatched id and key counts")
		}
		priv, err := hex.DecodeString(parsed.OneTimePrivates[i])
		if err != nil {
			return nil, fmt.Errorf("scs1: one-time prekey private is not valid hex: %w", err)
		}
		pub, err := hex.DecodeString(parsed.OneTimePublics[i])
		if err != nil {
			return nil, fmt.Errorf("scs1: one-time prekey public is not valid hex: %w", err)
		}
		privates[uint32(id)] = priv
		publics[uint32(id)] = pub
	}

	return protocol.NewPreKeyStoreFromParts(
		uint32(parsed.SignedPreKeyID), spkPriv, spkPub, sig, privates, publics,
	), nil
}
