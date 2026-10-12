package schedule

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
)

type pskVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	PSKs        []struct {
		PSKID    string `json:"psk_id"`
		PSK      string `json:"psk"`
		PSKNonce string `json:"psk_nonce"`
	} `json:"psks"`
	PSKSecret string `json:"psk_secret"`
}

// TestPSKSecretAgainstOfficialVectors is the acceptance criterion for psk_secret.
func TestPSKSecretAgainstOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "psk_secret.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []pskVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("psk_secret.json is not valid JSON: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("the vector file is empty")
	}

	checked, unsupported, emptyCases := 0, 0, 0
	maxPSKs := 0

	for i, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			unsupported++
			continue
		}

		want, err := hex.DecodeString(v.PSKSecret)
		if err != nil {
			t.Fatalf("vector %d: psk_secret is not hex: %v", i, err)
		}

		psks := make([]PSK, 0, len(v.PSKs))
		for j, p := range v.PSKs {
			id, err := hex.DecodeString(p.PSKID)
			if err != nil {
				t.Fatalf("vector %d psk %d: psk_id is not hex: %v", i, j, err)
			}
			secret, err := hex.DecodeString(p.PSK)
			if err != nil {
				t.Fatalf("vector %d psk %d: psk is not hex: %v", i, j, err)
			}
			nonce, err := hex.DecodeString(p.PSKNonce)
			if err != nil {
				t.Fatalf("vector %d psk %d: psk_nonce is not hex: %v", i, j, err)
			}
			psks = append(psks, PSK{ID: id, Secret: secret, Nonce: nonce})
		}
		if len(psks) > maxPSKs {
			maxPSKs = len(psks)
		}
		if len(psks) == 0 {
			emptyCases++
		}

		got, err := PSKSecret(psks, suite)
		if err != nil {
			t.Fatalf("vector %d (%d PSKs): %v", i, len(psks), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("vector %d (%d PSKs): psk_secret =\n  %x\nwant\n  %x", i, len(psks), got, want)
		}
		checked++
	}

	if checked == 0 {
		t.Fatal("no vector was checked for an implemented cipher suite")
	}
	if unsupported > 0 {
		t.Logf("skipped %d vectors for unimplemented cipher suites", unsupported)
	}
	t.Logf("verified %d psk_secret values (%d with no PSK, up to %d PSKs in one list); "+
		"the chain binds each PSK to its id and nonce via PSKLabel and one \"derived psk\" expansion",
		checked, emptyCases, maxPSKs)
}
