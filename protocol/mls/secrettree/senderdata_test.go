package secrettree

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
)

// The sender data keys, against the official vectors.
//
// Each vector publishes a sender_data_secret, a ciphertext, and the key and nonce that pair
// yields. That is enough to settle all three of the details that a plausible implementation
// could get wrong — the sample as context, the labels, and which length belongs to which value
// — without needing a group, a ratchet or a peer.

func TestSenderDataKeyNonceAgainstOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "secret-tree.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []secretTreeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("secret-tree.json is not valid JSON: %v", err)
	}

	checked, unsupported := 0, 0

	for i, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			unsupported++
			continue
		}

		key, nonce, err := SenderDataKeyNonce(
			mustHex(t, v.SenderData.SenderDataSecret),
			mustHex(t, v.SenderData.Ciphertext),
			suite)
		if err != nil {
			t.Fatalf("vector %d: SenderDataKeyNonce: %v", i, err)
		}

		if !bytes.Equal(key, mustHex(t, v.SenderData.Key)) {
			t.Errorf("vector %d: the sender data key =\n  %x\nwant\n  %s", i, key, v.SenderData.Key)
		}
		if !bytes.Equal(nonce, mustHex(t, v.SenderData.Nonce)) {
			t.Errorf("vector %d: the sender data nonce =\n  %x\nwant\n  %s", i, nonce, v.SenderData.Nonce)
		}
		checked += 2
	}

	if checked == 0 {
		t.Fatal("no vector was checked for an implemented cipher suite")
	}
	if unsupported > 0 {
		t.Logf("skipped %d vectors for unimplemented cipher suites", unsupported)
	}
	t.Logf("verified %d sender data keys and nonces", checked)
}

// TestSenderDataDependsOnTheCiphertext pins the property that makes the sample worth taking:
// the key belongs to ONE ciphertext. If it did not change with the ciphertext, the sample would
// be doing nothing and two different messages would share a key.
func TestSenderDataDependsOnTheCiphertext(t *testing.T) {
	suite := crypto.CipherSuite(0x0001)
	secret := make([]byte, suite.HashSize())
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	first := make([]byte, 64)
	second := make([]byte, 64)
	for i := range first {
		first[i] = 0xA0
		second[i] = 0xA0
	}
	// Differ only BEYOND the sample, so if the implementation used the whole ciphertext the
	// keys would differ, and if it used the sample they would match.
	second[suite.HashSize()+1] ^= 0xFF

	keyA, nonceA, err := SenderDataKeyNonce(secret, first, suite)
	if err != nil {
		t.Fatal(err)
	}
	keyB, nonceB, err := SenderDataKeyNonce(secret, second, suite)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA, keyB) || !bytes.Equal(nonceA, nonceB) {
		t.Fatal("changing the ciphertext BEYOND the sample changed the key, so the sample is not " +
			"the first HashSize bytes as the specification says")
	}

	// And a change INSIDE the sample must change them.
	third := append([]byte(nil), first...)
	third[0] ^= 0x01
	keyC, _, err := SenderDataKeyNonce(secret, third, suite)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyC) {
		t.Fatal("changing the first byte of the ciphertext did not change the key, so the sample " +
			"is not being used as the context")
	}
}

func TestSenderDataKeyNonceRejectsBadInput(t *testing.T) {
	suite := crypto.CipherSuite(0x0001)
	good := make([]byte, suite.HashSize())

	if _, _, err := SenderDataKeyNonce(make([]byte, 8), good, suite); err == nil {
		t.Fatal("a sender data secret of the wrong length was accepted")
	}
	// A ciphertext shorter than the sample: there is nothing to take, and padding it would
	// produce a sample the sender never used.
	if _, _, err := SenderDataKeyNonce(good, make([]byte, suite.HashSize()-1), suite); err == nil {
		t.Fatal("a ciphertext shorter than the sample was accepted")
	}
}
