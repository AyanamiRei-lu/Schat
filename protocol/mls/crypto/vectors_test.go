package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The official MLS test vectors are NOT vendored into this repository.
//
// The mls-implementations repository that publishes them carries no license file, which
// means the default applies: all rights reserved. Copying its JSON into SCHAT would be a
// licensing problem, so the vectors are fetched locally by tools/fetch-mls-vectors.ps1
// into a gitignored directory and these tests run only when they are present.
//
// That is a deliberate trade. The alternative — writing assertions against my own output —
// would test that the code agrees with itself, which is exactly the trap this project has
// already fallen into once (see the publish-path defect in SCHAT.md v0.8: every unit test
// passed while the feature had never worked).

type cryptoBasicsVector struct {
	CipherSuite uint16 `json:"cipher_suite"`

	RefHash *struct {
		Label string `json:"label"`
		Value string `json:"value"`
		Out   string `json:"out"`
	} `json:"ref_hash"`

	ExpandWithLabel *struct {
		Secret  string `json:"secret"`
		Label   string `json:"label"`
		Context string `json:"context"`
		Length  int    `json:"length"`
		Out     string `json:"out"`
	} `json:"expand_with_label"`

	DeriveSecret *struct {
		Secret string `json:"secret"`
		Label  string `json:"label"`
		Out    string `json:"out"`
	} `json:"derive_secret"`

	DeriveTreeSecret *struct {
		Secret     string `json:"secret"`
		Label      string `json:"label"`
		Generation int    `json:"generation"`
		Length     int    `json:"length"`
		Out        string `json:"out"`
	} `json:"derive_tree_secret"`

	SignWithLabel *struct {
		Priv      string `json:"priv"`
		Pub       string `json:"pub"`
		Content   string `json:"content"`
		Label     string `json:"label"`
		Signature string `json:"signature"`
	} `json:"sign_with_label"`

	EncryptWithLabel *struct {
		Priv       string `json:"priv"`
		Pub        string `json:"pub"`
		Label      string `json:"label"`
		Context    string `json:"context"`
		Plaintext  string `json:"plaintext"`
		KemOutput  string `json:"kem_output"`
		Ciphertext string `json:"ciphertext"`
	} `json:"encrypt_with_label"`
}

// vectorsPath is where tools/fetch-mls-vectors.ps1 puts the official vectors.
func vectorsPath(name string) string {
	return filepath.Join("..", "vectors", name)
}

func loadVectors(t *testing.T, name string, into any) bool {
	t.Helper()

	data, err := os.ReadFile(vectorsPath(name))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
		return false
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("%s is not valid JSON: %v", name, err)
	}
	return true
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("not valid hex: %q: %v", value, err)
	}
	return out
}

// TestCryptoBasicsAgainstOfficialVectors checks every labelled operation against the
// vectors the MLS working group publishes.
//
// This is the acceptance criterion for the crypto layer. Passing it means the label
// scheme, the length prefixes, the HPKE context construction and the signature structure
// all match the specification — none of which can be established by inspection, because
// every one of them is internally consistent even when it is wrong.
func TestCryptoBasicsAgainstOfficialVectors(t *testing.T) {
	var vectors []cryptoBasicsVector
	if !loadVectors(t, "crypto-basics.json", &vectors) {
		return
	}
	if len(vectors) == 0 {
		t.Fatal("the vector file contained no vectors")
	}

	checks := 0
	suites := map[CipherSuite]bool{}
	unsupported := map[uint16]int{}

	for i, v := range vectors {
		suite := CipherSuite(v.CipherSuite)

		// The vector file covers every registered suite, including the NIST-curve ones
		// (0x0002, 0x0004, 0x0005) that SCHAT will never use. Skipping them is honest as
		// long as it is COUNTED and reported: a silent skip would make "we pass the official
		// vectors" mean "we pass the subset we happened to run".
		if _, err := suite.Params(); err != nil {
			unsupported[v.CipherSuite]++
			continue
		}
		suites[suite] = true

		if v.ExpandWithLabel != nil {
			e := v.ExpandWithLabel
			got, err := ExpandWithLabel(
				mustHex(t, e.Secret), e.Label, mustHex(t, e.Context), e.Length, suite,
			)
			if err != nil {
				t.Fatalf("vector %d: ExpandWithLabel: %v", i, err)
			}
			if !equalHex(t, got, e.Out) {
				t.Errorf("vector %d: ExpandWithLabel(%q) = %x, want %s", i, e.Label, got, e.Out)
			}
			checks++
		}

		if v.DeriveSecret != nil {
			d := v.DeriveSecret
			got, err := DeriveSecret(mustHex(t, d.Secret), d.Label, suite)
			if err != nil {
				t.Fatalf("vector %d: DeriveSecret: %v", i, err)
			}
			if !equalHex(t, got, d.Out) {
				t.Errorf("vector %d: DeriveSecret(%q) = %x, want %s", i, d.Label, got, d.Out)
			}
			checks++
		}

		if v.DeriveTreeSecret != nil {
			d := v.DeriveTreeSecret
			// The generation is the context. If the specification meant something else,
			// this is where it shows up: the tree secrets are what every message key in a
			// group is derived from.
			got, err := DeriveTreeSecret(
				mustHex(t, d.Secret), d.Label, uint32(d.Generation), d.Length, suite,
			)
			if err != nil {
				t.Fatalf("vector %d: DeriveTreeSecret: %v", i, err)
			}
			if !equalHex(t, got, d.Out) {
				t.Errorf("vector %d: DeriveTreeSecret(%q, generation %d) = %x, want %s",
					i, d.Label, d.Generation, got, d.Out)
			}
			checks++
		}

		if v.RefHash != nil {
			r := v.RefHash
			got, err := RefHash(r.Label, mustHex(t, r.Value), suite)
			if err != nil {
				t.Fatalf("vector %d: RefHash: %v", i, err)
			}
			if !equalHex(t, got, r.Out) {
				t.Errorf("vector %d: RefHash(%q) = %x, want %s", i, r.Label, got, r.Out)
			}
			checks++
		}

		if v.SignWithLabel != nil {
			s := v.SignWithLabel
			priv := mustHex(t, s.Priv)
			pub := mustHex(t, s.Pub)
			content := mustHex(t, s.Content)
			signature := mustHex(t, s.Signature)

			// The vector's signature must verify under this implementation...
			if err := VerifyWithLabel(pub, s.Label, content, signature); err != nil {
				t.Errorf("vector %d: VerifyWithLabel(%q): %v", i, s.Label, err)
			}
			// ...and Ed25519 is deterministic, so producing it must give the same bytes.
			got, err := SignWithLabel(priv, s.Label, content)
			if err != nil {
				t.Fatalf("vector %d: SignWithLabel: %v", i, err)
			}
			if !equalHex(t, got, s.Signature) {
				t.Errorf("vector %d: SignWithLabel(%q) = %x, want %s", i, s.Label, got, s.Signature)
			}
			checks++
		}

		if v.EncryptWithLabel != nil {
			e := v.EncryptWithLabel
			priv := mustHex(t, e.Priv)
			pub := mustHex(t, e.Pub)
			context := mustHex(t, e.Context)
			plaintext := mustHex(t, e.Plaintext)

			// HPKE picks a fresh ephemeral key, so the vector's ciphertext cannot be
			// reproduced — but decrypting the vector's own ciphertext proves that the
			// EncryptContext (and the empty AAD) were constructed exactly as the
			// specification requires.
			got, err := DecryptWithLabel(priv, e.Label, context, mustHex(t, e.KemOutput), mustHex(t, e.Ciphertext), suite)
			if err != nil {
				t.Errorf("vector %d: DecryptWithLabel(%q): %v", i, e.Label, err)
			} else if string(got) != string(plaintext) {
				t.Errorf("vector %d: DecryptWithLabel(%q) = %x, want %x", i, e.Label, got, plaintext)
			}

			// And our own encryption must be readable by our own decryption.
			kemOutput, ciphertext, err := EncryptWithLabel(pub, e.Label, context, plaintext, suite)
			if err != nil {
				t.Fatalf("vector %d: EncryptWithLabel: %v", i, err)
			}
			roundTripped, err := DecryptWithLabel(priv, e.Label, context, kemOutput, ciphertext, suite)
			if err != nil {
				t.Fatalf("vector %d: round trip: %v", i, err)
			}
			if string(roundTripped) != string(plaintext) {
				t.Errorf("vector %d: round trip returned %x", i, roundTripped)
			}
			checks++
		}
	}

	if checks < len(vectors) {
		t.Errorf("only %d checks ran for %d vectors; a field name may not match the vector format",
			checks, len(vectors))
	}
	if len(suites) == 0 {
		t.Fatal("no vector was verified for any implemented cipher suite")
	}

	t.Logf("verified %d official crypto-basics checks across suites %v", checks, suiteNames(suites))
	if len(unsupported) > 0 {
		t.Logf("skipped %d vectors for cipher suites this project does not implement: %v",
			totalCount(unsupported), unsupported)
	}
}

// suiteNames renders the verified suites for the log line.
func suiteNames(suites map[CipherSuite]bool) []string {
	out := make([]string, 0, len(suites))
	for suite := range suites {
		out = append(out, fmt.Sprintf("%#04x", uint16(suite)))
	}
	sort.Strings(out)
	return out
}

func totalCount(counts map[uint16]int) int {
	total := 0
	for _, n := range counts {
		total += n
	}
	return total
}

func equalHex(t *testing.T, got []byte, wantHex string) bool {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("expected value is not hex: %v", err)
	}
	return string(got) == string(want)
}
