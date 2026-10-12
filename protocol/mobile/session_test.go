package mobile

import (
	"fmt"
	"strings"
	"testing"
)

// These tests drive the session API exactly as Kotlin will: strings and byte slices in,
// strings and byte slices out. They are the closest thing to a client-side integration
// test that can run without a device.

const testToken = "abababababababababababababababab"

func mustIdentityJSON(t *testing.T) string {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	blob, err := IdentityToJSON(id)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}
	return blob
}

// directoryBundleJSON renders the shape the relay's prekey directory serves.
func directoryBundleJSON(t *testing.T, storeJSON, responderBlob string, oneTimeID int64) (string, string) {
	t.Helper()

	bundle, err := PublishBundle(storeJSON, responderBlob, oneTimeID)
	if err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}

	oneTime := ""
	if bundle.OneTimePreKey != "" {
		oneTime = fmt.Sprintf(`{"id": %d, "public": %q}`, bundle.OneTimePreKeyID, bundle.OneTimePreKey)
	}

	raw := fmt.Sprintf(`{
	  "identity_signing": %q,
	  "identity_agreement": %q,
	  "signed_pre_key": %q,
	  "signed_pre_key_id": %d,
	  "signed_pre_key_signature": %q,
	  "one_time_pre_keys": [%s]
	}`,
		bundle.IdentitySigning,
		bundle.IdentityAgreement,
		bundle.SignedPreKey,
		bundle.SignedPreKeyID,
		bundle.SignedPreKeySignature,
		oneTime,
	)
	return raw, bundle.IdentitySigning
}

// newBoundPair performs a full handshake through the binding.
func newBoundPair(t *testing.T) (initiator, responder *Session) {
	t.Helper()

	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)

	storeJSON, err := CreatePreKeyStore(responderBlob, 3)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}

	wireBundle, responderIdentity := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	initiator, err = EstablishSession(initiatorBlob, responderIdentity, wireBundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}

	init := initiator.InitMessage()
	if len(init) == 0 {
		t.Fatal("the initiator produced no handshake message")
	}

	responder, err = AcceptSession(responderBlob, storeJSON, init)
	if err != nil {
		t.Fatalf("AcceptSession: %v", err)
	}
	return initiator, responder
}

func TestSessionRoundTripThroughTheBinding(t *testing.T) {
	initiator, responder := newBoundPair(t)
	defer initiator.Close()
	defer responder.Close()

	wire, err := initiator.Encrypt(testToken, []byte("hello from the initiator"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// The first sixteen bytes are the routing token and must be untouched.
	if !strings.HasPrefix(fmt.Sprintf("%x", wire[:16]), testToken[:4]) {
		t.Fatal("the delivery token was not written into the envelope")
	}

	got, err := responder.Decrypt(wire)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "hello from the initiator" {
		t.Fatalf("got %q", got)
	}

	// And back the other way.
	wire, err = responder.Encrypt(testToken, []byte("hello back"), "text")
	if err != nil {
		t.Fatalf("Encrypt (responder): %v", err)
	}
	got, err = initiator.Decrypt(wire)
	if err != nil {
		t.Fatalf("Decrypt (initiator): %v", err)
	}
	if string(got) != "hello back" {
		t.Fatalf("got %q", got)
	}
}

func TestSessionRoundTripAcrossProfiles(t *testing.T) {
	initiator, responder := newBoundPair(t)
	defer initiator.Close()
	defer responder.Close()

	for _, profile := range []string{"text", "image", "video", "file", "voice", "header", "database"} {
		want := "payload for " + profile
		wire, err := initiator.Encrypt(testToken, []byte(want), profile)
		if err != nil {
			t.Fatalf("Encrypt(%s): %v", profile, err)
		}
		got, err := responder.Decrypt(wire)
		if err != nil {
			t.Fatalf("Decrypt(%s): %v", profile, err)
		}
		if string(got) != want {
			t.Fatalf("%s: got %q", profile, got)
		}
	}
}

// TestBundleIdentityMismatchIsRejected is the documented client-side obligation: the
// directory does not authenticate publishers, so a bundle whose identity is not the one
// requested must be refused before it is used.
func TestBundleIdentityMismatchIsRejected(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)

	storeJSON, err := CreatePreKeyStore(responderBlob, 2)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	wireBundle, _ := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	// Ask for a different identity than the bundle answers for.
	otherIdentity := strings.Repeat("cd", 32)

	if _, err := EstablishSession(initiatorBlob, otherIdentity, wireBundle); err == nil {
		t.Fatal("a bundle for the wrong identity was accepted")
	}
}

func TestEstablishSessionRejectsMissingPeerIdentity(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)
	storeJSON, _ := CreatePreKeyStore(responderBlob, 2)
	wireBundle, _ := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	if _, err := EstablishSession(initiatorBlob, "", wireBundle); err == nil {
		t.Fatal("a handshake without an expected peer identity was allowed")
	}
}

func TestEstablishSessionRejectsMalformedInput(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)
	storeJSON, _ := CreatePreKeyStore(responderBlob, 2)
	wireBundle, responderIdentity := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	if _, err := EstablishSession("not json", responderIdentity, wireBundle); err == nil {
		t.Error("expected an error for a malformed identity")
	}
	if _, err := EstablishSession(initiatorBlob, responderIdentity, "not json"); err == nil {
		t.Error("expected an error for a malformed bundle")
	}
}

func TestAcceptSessionRejectsMalformedHandshake(t *testing.T) {
	responderBlob := mustIdentityJSON(t)
	storeJSON, _ := CreatePreKeyStore(responderBlob, 2)

	if _, err := AcceptSession(responderBlob, storeJSON, []byte("too short")); err == nil {
		t.Error("expected an error for a truncated handshake message")
	}
	if _, err := AcceptSession(responderBlob, storeJSON, nil); err == nil {
		t.Error("expected an error for a nil handshake message")
	}
}

/** A replayed handshake must fail rather than silently reuse a one-time prekey. */
func TestAcceptSessionRejectsReplay(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)
	storeJSON, _ := CreatePreKeyStore(responderBlob, 2)
	wireBundle, responderIdentity := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	initiator, err := EstablishSession(initiatorBlob, responderIdentity, wireBundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	defer initiator.Close()

	init := initiator.InitMessage()

	first, err := AcceptSession(responderBlob, storeJSON, init)
	if err != nil {
		t.Fatalf("first AcceptSession: %v", err)
	}
	defer first.Close()

	// The client's obligation: persist the consumed pool over the old one.
	updated := first.UpdatedPreKeyStore()
	if updated == "" {
		t.Fatal("the responder session did not report an updated prekey pool")
	}
	if updated == storeJSON {
		t.Fatal("the updated prekey pool is identical to the old one; nothing was consumed")
	}

	// Replaying the same handshake against the UPDATED pool must fail, because the
	// one-time prekey it names is gone.
	if _, err := AcceptSession(responderBlob, updated, init); err == nil {
		t.Fatal("a replayed handshake reused the same one-time prekey")
	}
}

/**
 * Documents that the one-time property depends on the client persisting the update.
 *
 * Replaying against the stale pool succeeds, which is why UpdatedPreKeyStore exists and
 * why the client must call it. The test states the limitation rather than hiding it.
 */
func TestReplayAgainstAStalePoolIsPossible(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)
	storeJSON, _ := CreatePreKeyStore(responderBlob, 2)
	wireBundle, responderIdentity := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	initiator, err := EstablishSession(initiatorBlob, responderIdentity, wireBundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	defer initiator.Close()
	init := initiator.InitMessage()

	first, err := AcceptSession(responderBlob, storeJSON, init)
	if err != nil {
		t.Fatalf("first AcceptSession: %v", err)
	}
	first.Close()

	// The stale pool still contains the prekey, so the replay is accepted. This is the
	// failure mode the client avoids by saving UpdatedPreKeyStore immediately.
	replay, err := AcceptSession(responderBlob, storeJSON, init)
	if err != nil {
		t.Skip("the replay was refused, which is stronger than required")
	}
	replay.Close()
	t.Log("confirmed: a replay against a stale pool succeeds, so the client must persist the update")
}

func TestInitUpdatedPreKeyStoreIsEmptyForAnInitiator(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()

	if initiator.UpdatedPreKeyStore() != "" {
		t.Error("an initiator's session reported an updated prekey pool")
	}
}

// TestSnapshotThroughTheBinding is the property the client depends on across a restart.
func TestSnapshotThroughTheBinding(t *testing.T) {
	initiator, responder := newBoundPair(t)

	wire, err := initiator.Encrypt(testToken, []byte("before the snapshot"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := responder.Decrypt(wire); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	snapshot, err := initiator.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot) == 0 {
		t.Fatal("Snapshot produced nothing")
	}
	initiator.Close()

	restored, err := RestoreSession(snapshot)
	if err != nil {
		t.Fatalf("RestoreSession: %v", err)
	}
	defer restored.Close()

	// The responder can still reach the restored client...
	wire, err = responder.Encrypt(testToken, []byte("after the restart"), "text")
	if err != nil {
		t.Fatalf("Encrypt (responder): %v", err)
	}
	got, err := restored.Decrypt(wire)
	if err != nil {
		t.Fatalf("Decrypt (restored): %v", err)
	}
	if string(got) != "after the restart" {
		t.Fatalf("got %q", got)
	}

	// ...and the restored client can still reach the responder.
	wire, err = restored.Encrypt(testToken, []byte("still alive"), "text")
	if err != nil {
		t.Fatalf("Encrypt (restored): %v", err)
	}
	if _, err := responder.Decrypt(wire); err != nil {
		t.Fatalf("Decrypt (responder): %v", err)
	}

	if restored.RatchetPublic() == "" {
		t.Error("the restored session reported no ratchet key")
	}
	_ = restored.SendCounter()
	_ = restored.RecvCounter()
	_ = restored.SkippedKeyCount()
}

func TestRestoreSessionRejectsGarbage(t *testing.T) {
	if _, err := RestoreSession([]byte("not a snapshot")); err == nil {
		t.Fatal("expected an error for a malformed snapshot")
	}
	if _, err := RestoreSession(nil); err == nil {
		t.Fatal("expected an error for a nil snapshot")
	}
}

func TestEncryptRejectsBadInput(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()

	if _, err := initiator.Encrypt("not hex", []byte("x"), "text"); err == nil {
		t.Error("expected an error for a non-hex token")
	}
	if _, err := initiator.Encrypt("aabb", []byte("x"), "text"); err == nil {
		t.Error("expected an error for a short token")
	}
	if _, err := initiator.Encrypt(testToken, []byte("x"), "nonsense"); err == nil {
		t.Error("expected an error for an unknown content profile")
	}
}

/** A nil or closed session must fail cleanly rather than panicking in the client. */
func TestClosedSessionIsSafeToUse(t *testing.T) {
	initiator, _ := newBoundPair(t)
	initiator.Close()

	if _, err := initiator.Encrypt(testToken, []byte("x"), "text"); err == nil {
		t.Error("expected an error after Close")
	}
	if _, err := initiator.Decrypt([]byte("x")); err == nil {
		t.Error("expected an error after Close")
	}
	if _, err := initiator.Snapshot(); err == nil {
		t.Error("expected an error after Close")
	}
	initiator.Close() // must not panic when called twice
}

func TestDecryptRejectsShortWireData(t *testing.T) {
	_, responder := newBoundPair(t)
	defer responder.Close()

	if _, err := responder.Decrypt([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected an error for a truncated envelope")
	}
}

// ---- content type framing ------------------------------------------------
//
// The relay forwards opaque bytes, so a mailbox carries two kinds of payload: an
// encrypted frame, and a plaintext handshake initiation that has to arrive before any
// session exists. A type byte is what lets the receiver tell them apart.

func TestEncryptTagsThePayloadAsAFrame(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()

	wire, err := initiator.Encrypt(testToken, []byte("hello"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	kind, err := ContentType(wire)
	if err != nil {
		t.Fatalf("ContentType: %v", err)
	}
	if kind != ContentTypeFrame {
		t.Fatalf("content type is %#x, want a frame", kind)
	}
}

func TestDecryptRefusesAHandshakePayload(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()

	wire, err := WrapHandshake(testToken, make([]byte, 138))
	if err != nil {
		t.Fatalf("WrapHandshake: %v", err)
	}

	// A handshake handed to the ratchet must be refused, not misparsed.
	if _, err := initiator.Decrypt(wire); err == nil {
		t.Fatal("a handshake payload was accepted as an encrypted frame")
	}
}

func TestHandshakeWrappingRoundTrips(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()

	init := initiator.InitMessage()
	wire, err := WrapHandshake(testToken, init)
	if err != nil {
		t.Fatalf("WrapHandshake: %v", err)
	}

	kind, err := ContentType(wire)
	if err != nil {
		t.Fatalf("ContentType: %v", err)
	}
	if kind != ContentTypeHandshake {
		t.Fatalf("content type is %#x, want a handshake", kind)
	}

	got, err := UnwrapHandshake(wire)
	if err != nil {
		t.Fatalf("UnwrapHandshake: %v", err)
	}
	if string(got) != string(init) {
		t.Fatal("the handshake message did not survive the round trip")
	}
}

func TestUnwrapHandshakeRefusesAFrame(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()

	wire, err := initiator.Encrypt(testToken, []byte("hello"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := UnwrapHandshake(wire); err == nil {
		t.Fatal("an encrypted frame was accepted as a handshake")
	}
}

func TestWrapHandshakeRejectsBadInput(t *testing.T) {
	initiator, _ := newBoundPair(t)
	defer initiator.Close()
	init := initiator.InitMessage()

	if _, err := WrapHandshake("not hex", init); err == nil {
		t.Error("expected an error for a non-hex token")
	}
	if _, err := WrapHandshake("aabb", init); err == nil {
		t.Error("expected an error for a short token")
	}
	if _, err := WrapHandshake(testToken, init[:100]); err == nil {
		t.Error("expected an error for a truncated handshake")
	}
	if _, err := WrapHandshake(testToken, nil); err == nil {
		t.Error("expected an error for an empty handshake")
	}
}

func TestContentTypeRejectsShortPayloads(t *testing.T) {
	if _, err := ContentType(nil); err == nil {
		t.Error("expected an error for an empty payload")
	}
	if _, err := ContentType(make([]byte, 16)); err == nil {
		t.Error("expected an error for a token with no content type")
	}
}

/**
 * The MVP's core path, end to end through the binding: a handshake travels as a typed
 * relay payload, the responder rebuilds its prekey pool, and text flows both ways.
 */
func TestFullHandshakeOverTheRelayPayloadFormat(t *testing.T) {
	initiatorBlob := mustIdentityJSON(t)
	responderBlob := mustIdentityJSON(t)

	storeJSON, err := CreatePreKeyStore(responderBlob, 3)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	wireBundle, responderIdentity := directoryBundleJSON(t, storeJSON, responderBlob, 1)

	// The initiator publishes nothing and fetches the responder's bundle, then wraps the
	// handshake addressed to the responder's mailbox.
	initiator, err := EstablishSession(initiatorBlob, responderIdentity, wireBundle)
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	defer initiator.Close()

	relayedHandshake, err := WrapHandshake(testToken, initiator.InitMessage())
	if err != nil {
		t.Fatalf("WrapHandshake: %v", err)
	}

	// The responder receives it from the relay and must route on the content type.
	kind, err := ContentType(relayedHandshake)
	if err != nil {
		t.Fatalf("ContentType: %v", err)
	}
	if kind != ContentTypeHandshake {
		t.Fatalf("expected a handshake, got content type %#x", kind)
	}

	initBytes, err := UnwrapHandshake(relayedHandshake)
	if err != nil {
		t.Fatalf("UnwrapHandshake: %v", err)
	}

	responder, err := AcceptSession(responderBlob, storeJSON, initBytes)
	if err != nil {
		t.Fatalf("AcceptSession: %v", err)
	}
	defer responder.Close()

	if responder.UpdatedPreKeyStore() == "" {
		t.Fatal("the responder did not report a consumed prekey pool")
	}

	// Text in both directions.
	wire, err := initiator.Encrypt(testToken, []byte("first message"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := responder.Decrypt(wire)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "first message" {
		t.Fatalf("got %q", got)
	}

	wire, err = responder.Encrypt(testToken, []byte("first reply"), "text")
	if err != nil {
		t.Fatalf("Encrypt (responder): %v", err)
	}
	got, err = initiator.Decrypt(wire)
	if err != nil {
		t.Fatalf("Decrypt (initiator): %v", err)
	}
	if string(got) != "first reply" {
		t.Fatalf("got %q", got)
	}
}
