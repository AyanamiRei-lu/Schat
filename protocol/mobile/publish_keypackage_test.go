package mobile

import (
	"encoding/json"
	"strings"
	"testing"
)

// The KeyPackage inside the published bundle.
//
// The field exists so that another member can add this client to a group without an exchange out
// of band. Two things about it are worth pinning rather than assuming:
//
//   - when there is no KeyPackage, the field must be ABSENT and not merely empty. The server
//     validates what it is given, and a client that published `"key_package": ""` would be
//     publishing a malformed one — the old behaviour has to stay byte-identical for clients
//     that have no group support;
//   - when there is one, it must arrive unchanged. A KeyPackage is signed over its own bytes,
//     so a single altered character makes it one that nobody can verify and therefore nobody
//     can safely add.

func testBundleStore(t *testing.T, identityJSON string) string {
	t.Helper()
	store, err := CreatePreKeyStore(identityJSON, 4)
	if err != nil {
		t.Fatalf("CreatePreKeyStore: %v", err)
	}
	return store
}

func TestPublishingWithoutAKeyPackageOmitsTheField(t *testing.T) {
	identity := testIdentityJSON(t)
	store := testBundleStore(t, identity)

	plain, err := PublishBundleJSON(store, identity)
	if err != nil {
		t.Fatalf("PublishBundleJSON: %v", err)
	}

	if strings.Contains(plain, "key_package") {
		t.Fatalf("a client that published no KeyPackage still produced a key_package field:\n%s", plain)
	}

	// And it must still parse as a bundle with everything a handshake needs.
	var decoded map[string]any
	if err := json.Unmarshal([]byte(plain), &decoded); err != nil {
		t.Fatalf("the bundle is not valid JSON: %v", err)
	}
	for _, required := range []string{"identity_signing", "identity_agreement", "signed_pre_key", "signed_pre_key_signature"} {
		if _, ok := decoded[required]; !ok {
			t.Fatalf("the bundle lost the %q field", required)
		}
	}
}

func TestPublishingWithAKeyPackageCarriesItUnchanged(t *testing.T) {
	identity := testIdentityJSON(t)
	store := testBundleStore(t, identity)

	keyPackage, err := GroupKeyPackage(identity)
	if err != nil {
		t.Fatalf("GroupKeyPackage: %v", err)
	}

	withKeyPackage, err := PublishBundleJSONWithKeyPackage(store, identity, keyPackage.KeyPackageHex)
	if err != nil {
		t.Fatalf("PublishBundleJSONWithKeyPackage: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(withKeyPackage), &decoded); err != nil {
		t.Fatalf("the bundle is not valid JSON: %v", err)
	}

	carried, ok := decoded["key_package"]
	if !ok {
		t.Fatal("the bundle carries no key_package field, so another member has no way to add " +
			"this client to a group")
	}
	if carried != keyPackage.KeyPackageHex {
		t.Fatal("the KeyPackage was altered on its way into the bundle; it is signed over its own " +
			"bytes, so an altered one can never be verified and never be safely added")
	}

	// Everything a one-to-one handshake needs must still be there: adding a field must not
	// disturb the ones the existing protocol depends on.
	for _, required := range []string{"identity_signing", "identity_agreement", "signed_pre_key", "signed_pre_key_signature"} {
		if _, ok := decoded[required]; !ok {
			t.Fatalf("adding a KeyPackage lost the %q field", required)
		}
	}
}

func TestPublishingRefusesANonHexKeyPackage(t *testing.T) {
	identity := testIdentityJSON(t)
	store := testBundleStore(t, identity)

	// The server would reject this, and it cannot be a mistake the user can fix — so it is
	// refused here, where the caller can be told which side produced it.
	if _, err := PublishBundleJSONWithKeyPackage(store, identity, "not hex"); err == nil {
		t.Fatal("a non-hex KeyPackage was accepted into a bundle")
	}
	if _, err := PublishBundleJSONWithKeyPackage(store, identity, "abc"); err == nil {
		t.Fatal("an odd-length hex KeyPackage was accepted")
	}
}
