package secrettree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// The official secret-tree vectors. This is one of the few parts of the group machinery that
// can be checked byte for byte rather than argued about: the vector gives the epoch's
// encryption secret and then, for each leaf and generation, the four derived values.
//
// It settles every one of the shapes that a plausible implementation could get wrong: the
// "tree"/"left"/"right" context, the empty context on the ratchet roots, the generation as a
// big-endian uint32, and the AEAD lengths for the key and nonce against the hash length for
// everything else.

type secretTreeVector struct {
	CipherSuite      uint16 `json:"cipher_suite"`
	EncryptionSecret string `json:"encryption_secret"`
	SenderData       struct {
		SenderDataSecret string `json:"sender_data_secret"`
		Ciphertext       string `json:"ciphertext"`
		Key              string `json:"key"`
		Nonce            string `json:"nonce"`
	} `json:"sender_data"`
	Leaves [][]struct {
		Generation       uint32 `json:"generation"`
		ApplicationKey   string `json:"application_key"`
		ApplicationNonce string `json:"application_nonce"`
		HandshakeKey     string `json:"handshake_key"`
		HandshakeNonce   string `json:"handshake_nonce"`
	} `json:"leaves"`
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("not hex: %q", value)
	}
	return out
}

func TestSecretTreeAgainstOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "secret-tree.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []secretTreeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("secret-tree.json is not valid JSON: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("the vector file is empty")
	}

	checked, leaves, unsupported := 0, 0, 0

	for i, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			unsupported++
			continue
		}

		tree, err := New(mustHex(t, v.EncryptionSecret), uint32(len(v.Leaves)), suite)
		if err != nil {
			t.Fatalf("vector %d: New: %v", i, err)
		}

		for leafIndex, generations := range v.Leaves {
			application, err := tree.ApplicationRatchet(uint32(leafIndex))
			if err != nil {
				t.Fatalf("vector %d leaf %d: %v", i, leafIndex, err)
			}
			handshake, err := tree.HandshakeRatchet(uint32(leafIndex))
			if err != nil {
				t.Fatalf("vector %d leaf %d: %v", i, leafIndex, err)
			}

			for _, expected := range generations {
				for _, kind := range []struct {
					name    string
					ratchet *Ratchet
					key     string
					nonce   string
				}{
					{"application", application, expected.ApplicationKey, expected.ApplicationNonce},
					{"handshake", handshake, expected.HandshakeKey, expected.HandshakeNonce},
				} {
					key, nonce, err := kind.ratchet.KeyNonceAt(expected.Generation)
					if err != nil {
						t.Fatalf("vector %d leaf %d generation %d (%s): %v",
							i, leafIndex, expected.Generation, kind.name, err)
					}
					if !bytes.Equal(key, mustHex(t, kind.key)) {
						t.Errorf("vector %d leaf %d generation %d: the %s key =\n  %x\nwant\n  %s",
							i, leafIndex, expected.Generation, kind.name, key, kind.key)
					}
					if !bytes.Equal(nonce, mustHex(t, kind.nonce)) {
						t.Errorf("vector %d leaf %d generation %d: the %s nonce =\n  %x\nwant\n  %s",
							i, leafIndex, expected.Generation, kind.name, nonce, kind.nonce)
					}
					checked += 2
				}
			}
			leaves++
		}
	}

	if checked == 0 {
		t.Fatal("no value was checked for an implemented cipher suite")
	}
	if unsupported > 0 {
		t.Logf("skipped %d vectors for unimplemented cipher suites", unsupported)
	}
	t.Logf("verified %d ratchet keys and nonces across %d leaves", checked, leaves)
}

// TestTheTwoRatchetsAgreeWithNothingButThemselves pins the separation between the handshake and
// application ratchets. They are two sequences, not one sequence with two labels, and a member
// that drew both from one would reuse a nonce — the one failure an AEAD cannot survive.
func TestTheTwoRatchetsAgreeWithNothingButThemselves(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "secret-tree.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}
	var vectors []secretTreeVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			continue
		}

		tree, err := New(mustHex(t, v.EncryptionSecret), uint32(len(v.Leaves)), suite)
		if err != nil {
			t.Fatal(err)
		}
		application, err := tree.ApplicationRatchet(0)
		if err != nil {
			t.Fatal(err)
		}
		handshake, err := tree.HandshakeRatchet(0)
		if err != nil {
			t.Fatal(err)
		}

		aKey, aNonce, err := application.KeyNonceAt(0)
		if err != nil {
			t.Fatal(err)
		}
		hKey, hNonce, err := handshake.KeyNonceAt(0)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(aKey, hKey) || bytes.Equal(aNonce, hNonce) {
			t.Fatal("the application and handshake ratchets produce the same key or nonce at " +
				"generation 0, so they are not separate sequences")
		}
		return
	}
}

func TestRatchetRefusesToGoBackwards(t *testing.T) {
	suite := crypto.CipherSuite(0x0001)
	secret := make([]byte, suite.HashSize())
	for i := range secret {
		secret[i] = 0x11
	}

	tree, err := New(secret, 2, suite)
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := tree.ApplicationRatchet(0)
	if err != nil {
		t.Fatal(err)
	}

	// Forward is fine, and does not move the ratchet.
	if _, _, err := ratchet.KeyNonceAt(5); err != nil {
		t.Fatalf("a later generation could not be computed: %v", err)
	}
	if ratchet.Generation != 0 {
		t.Fatal("KeyNonceAt moved the ratchet; it must not, or a receiver checking a later " +
			"generation would lose the ones in between")
	}

	for i := 0; i < 3; i++ {
		if err := ratchet.Advance(); err != nil {
			t.Fatal(err)
		}
	}

	// And backwards must be refused rather than silently recomputed: the secret for an earlier
	// generation has been consumed, and section 9.2 requires it to be gone.
	if _, _, err := ratchet.KeyNonceAt(1); err == nil {
		t.Fatal("a consumed generation was recomputed, which means the ratchet kept a secret it " +
			"was required to delete")
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	suite := crypto.CipherSuite(0x0001)
	good := make([]byte, suite.HashSize())

	if _, err := New(good, 3, suite); err == nil {
		t.Fatal("three leaves was accepted; the layout requires a power of two")
	}
	if _, err := New(make([]byte, 8), 2, suite); err == nil {
		t.Fatal("an encryption secret of the wrong length was accepted")
	}
}
