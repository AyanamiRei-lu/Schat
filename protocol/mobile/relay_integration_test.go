package mobile

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// RelayURLEnv names the environment variable that points this test at a running relay,
// for example https://127.0.0.1:8443.
//
// The test is skipped without it, because it needs a process this package cannot start:
// the protocol module must not depend on the server module, and a unit test that reached
// across that boundary would be the first step toward the client binding importing
// server code — which is exactly what the architecture forbids.
const RelayURLEnv = "SCHAT_RELAY_URL"

// TestPublishAndFetchAgainstALiveRelay exercises the real HTTP directory.
//
// # Why this exists next to the pure unit tests
//
// TestPublishBundleJSONCarriesTheWholePool checks the published field names against a
// struct declared in this package — that is, against our own mirror of the server's
// format. If both the mirror and the producer were wrong in the same way, the test would
// still pass and no client could ever be reached. This test removes the mirror: it talks
// to a real `schat-server`, and the assertion that matters is that a bundle produced by
// PublishBundleJSON is accepted, stored, handed back in the shape EstablishSession wants,
// and that fetching twice consumes two DIFFERENT one-time prekeys.
//
// Run it with:
//
//	$env:SCHAT_RELAY_URL = "https://127.0.0.1:8443"
//	cd protocol && go test ./mobile/ -run LiveRelay -v
func TestPublishAndFetchAgainstALiveRelay(t *testing.T) {
	base := strings.TrimSpace(os.Getenv(RelayURLEnv))
	if base == "" {
		t.Skipf("set %s to a running relay to enable this test", RelayURLEnv)
	}
	base = strings.TrimRight(base, "/")

	// The relay presents a self-signed certificate and the fingerprint is the natural
	// thing to pin, but pinning it here would duplicate PinnedTrust's job. This is a
	// test harness: what is under test is the JSON contract, not the transport.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test harness
		},
	}

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

	// 1. Publish. A 400 here means the client and server disagree on the field names,
	//    which is the failure this test exists to catch. A 404 means the identity is not
	//    in the path, which the relay requires even for a PUT.
	keyURL := base + "/api/v1/keys/" + responder.SigningPublic
	putReq, err := http.NewRequest(http.MethodPut, keyURL, bytes.NewReader([]byte(published)))
	if err != nil {
		t.Fatalf("building PUT: %v", err)
	}
	putReq.Header.Set("Content-Type", "application/json")

	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("PUT %s: %v", keyURL, err)
	}
	putBody := drain(t, putResp)
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("the relay rejected a bundle this client produced: HTTP %d: %s",
			putResp.StatusCode, putBody)
	}
	t.Logf("published: %s", putBody)

	// 2. Fetch it twice. The directory consumes one one-time prekey per fetch, and the
	//    whole forward-secrecy argument rests on the two being different.
	firstID, firstJSON := fetchBundle(t, client, base, responder.SigningPublic)
	secondID, secondJSON := fetchBundle(t, client, base, responder.SigningPublic)

	if firstID == 0 {
		t.Fatal("the first fetch returned no one-time prekey")
	}
	if secondID == 0 {
		t.Fatalf("the pool held %d prekeys but the second fetch was already empty", poolSize)
	}
	if firstID == secondID {
		t.Fatalf("both fetches received one-time prekey %d; it is not one-time", firstID)
	}

	// 3. The decisive step: a session must come out of what the server actually served.
	initiator, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	initiatorBlob, err := IdentityToJSON(initiator)
	if err != nil {
		t.Fatalf("IdentityToJSON: %v", err)
	}

	session, err := EstablishSession(initiatorBlob, responder.SigningPublic, firstJSON)
	if err != nil {
		t.Fatalf("a bundle fetched from the relay was rejected by EstablishSession: %v", err)
	}
	defer session.Close()

	// The second fetch must be just as usable: draining the pool hands out a different
	// prekey, not a broken bundle.
	secondSession, err := EstablishSession(initiatorBlob, responder.SigningPublic, secondJSON)
	if err != nil {
		t.Fatalf("the second fetched bundle was rejected by EstablishSession: %v", err)
	}
	secondSession.Close()

	// 4. The responder accepts, and the two ends must complete a real round trip. This
	//    is the same sequence the chat controller performs on a device.
	accepted, err := AcceptSession(responderBlob, storeJSON, session.InitMessage())
	if err != nil {
		t.Fatalf("AcceptSession: %v", err)
	}
	defer accepted.Close()

	if got := accepted.PeerIdentity(); got != initiator.SigningPublic {
		t.Fatalf("the responder learned peer %s, want %s", got, initiator.SigningPublic)
	}
	if got := session.PeerIdentity(); got != responder.SigningPublic {
		t.Fatalf("the initiator learned peer %s, want %s", got, responder.SigningPublic)
	}

	wire, err := session.Encrypt(testToken, []byte("live relay round trip"), "text")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := accepted.Decrypt(wire)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != "live relay round trip" {
		t.Fatalf("decrypted %q", plain)
	}

	// 5. Leave nothing behind on the relay: it holds public keys only, but a test that
	//    litters a shared server is a test that eventually breaks someone else's run.
	delReq, err := http.NewRequest(http.MethodDelete, base+"/api/v1/keys/"+responder.SigningPublic, nil)
	if err != nil {
		t.Fatalf("building DELETE: %v", err)
	}
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	drain(t, delResp)
	if delResp.StatusCode != http.StatusOK {
		t.Logf("warning: the test bundle was not withdrawn (HTTP %d)", delResp.StatusCode)
	}
}

// fetchBundle performs one GET and reports the one-time prekey id it carried.
func fetchBundle(t *testing.T, client *http.Client, base, identityHex string) (int64, string) {
	t.Helper()

	resp, err := client.Get(base + "/api/v1/keys/" + identityHex)
	if err != nil {
		t.Fatalf("GET bundle: %v", err)
	}
	body := drain(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the relay would not serve the bundle just published: HTTP %d: %s",
			resp.StatusCode, body)
	}

	// Parsed with the same struct the binding uses, so a shape the binding could not
	// read shows up as a decoding difference rather than passing silently.
	var parsed bundleJSON
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("the relay served a bundle that is not valid JSON: %v", err)
	}
	if parsed.IdentitySigning != strings.ToLower(identityHex) {
		t.Fatalf("the relay served identity %s, want %s", parsed.IdentitySigning, identityHex)
	}

	if len(parsed.OneTimePreKeys) > 1 {
		t.Fatalf("the relay served %d one-time prekeys at once; it must serve at most one",
			len(parsed.OneTimePreKeys))
	}
	if len(parsed.OneTimePreKeys) == 0 {
		return 0, body
	}
	return parsed.OneTimePreKeys[0].ID, body
}

func drain(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading the response body: %v", err)
	}
	return string(body)
}
