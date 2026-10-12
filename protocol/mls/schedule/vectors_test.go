package schedule

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/schat/schat/protocol/mls/crypto"
)

// The official MLS test vectors are not vendored; see the note in protocol/mls/crypto.
// tools/fetch-mls-vectors.ps1 puts them in ../vectors, and this test skips when they are
// absent so that an ordinary offline `go test ./...` stays green.

type keyScheduleEpoch struct {
	CommitSecret            string `json:"commit_secret"`
	ConfirmedTranscriptHash string `json:"confirmed_transcript_hash"`
	PskSecret               string `json:"psk_secret"`
	TreeHash                string `json:"tree_hash"`
	GroupContext            string `json:"group_context"`

	JoinerSecret       string `json:"joiner_secret"`
	WelcomeSecret      string `json:"welcome_secret"`
	InitSecret         string `json:"init_secret"`
	SenderDataSecret   string `json:"sender_data_secret"`
	EncryptionSecret   string `json:"encryption_secret"`
	ExporterSecret     string `json:"exporter_secret"`
	EpochAuthenticator string `json:"epoch_authenticator"`
	ExternalSecret     string `json:"external_secret"`
	ExternalPub        string `json:"external_pub"`
	ConfirmationKey    string `json:"confirmation_key"`
	MembershipKey      string `json:"membership_key"`
	ResumptionPSK      string `json:"resumption_psk"`

	Exporter struct {
		Label   string `json:"label"`
		Context string `json:"context"`
		Length  int    `json:"length"`
		Secret  string `json:"secret"`
	} `json:"exporter"`
}

type keyScheduleVector struct {
	CipherSuite       uint16             `json:"cipher_suite"`
	GroupID           string             `json:"group_id"`
	InitialInitSecret string             `json:"initial_init_secret"`
	Epochs            []keyScheduleEpoch `json:"epochs"`
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("not hex: %q", value)
	}
	return out
}

func equalHex(t *testing.T, got []byte, wantHex string) bool {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("expected value is not hex: %v", err)
	}
	return string(got) == string(want)
}

// TestKeyScheduleAgainstOfficialVectors is the acceptance criterion for this milestone.
func TestKeyScheduleAgainstOfficialVectors(t *testing.T) {
	path := filepath.Join("..", "vectors", "key-schedule.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []keyScheduleVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("key-schedule.json is not valid JSON: %v", err)
	}

	checked, epochs := 0, 0
	unsupported := 0

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			unsupported++
			continue
		}

		initSecret := mustHex(t, v.InitialInitSecret)
		groupID := mustHex(t, v.GroupID)

		for i, e := range v.Epochs {
			gc := GroupContext{
				Version:                 ProtocolVersion,
				CipherSuite:             v.CipherSuite,
				GroupID:                 groupID,
				Epoch:                   uint64(i),
				TreeHash:                mustHex(t, e.TreeHash),
				ConfirmedTranscriptHash: mustHex(t, e.ConfirmedTranscriptHash),
			}

			// The group context is the easy half and it is checked first: if its encoding
			// is wrong, every secret derived from it is wrong for a reason that has nothing
			// to do with the key schedule.
			encoded, err := gc.Marshal()
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: Marshal: %v", v.CipherSuite, i, err)
			}
			if !equalHex(t, encoded, e.GroupContext) {
				t.Fatalf("suite %#04x epoch %d: group context =\n  %x\nwant\n  %s",
					v.CipherSuite, i, encoded, e.GroupContext)
			}
			checked++

			got, err := KeySchedule(
				initSecret,
				mustHex(t, e.CommitSecret),
				mustHex(t, e.PskSecret),
				gc,
				suite,
			)
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: KeySchedule: %v", v.CipherSuite, i, err)
			}

			fields := []struct {
				name string
				got  []byte
				want string
			}{
				{"joiner_secret", got.JoinerSecret, e.JoinerSecret},
				{"welcome_secret", got.WelcomeSecret, e.WelcomeSecret},
				{"init_secret", got.InitSecret, e.InitSecret},
				{"sender_data_secret", got.SenderDataSecret, e.SenderDataSecret},
				{"encryption_secret", got.EncryptionSecret, e.EncryptionSecret},
				{"exporter_secret", got.ExporterSecret, e.ExporterSecret},
				{"epoch_authenticator", got.EpochAuthenticator, e.EpochAuthenticator},
				{"external_secret", got.ExternalSecret, e.ExternalSecret},
				{"confirmation_key", got.ConfirmationKey, e.ConfirmationKey},
				{"membership_key", got.MembershipKey, e.MembershipKey},
				{"resumption_psk", got.ResumptionPSK, e.ResumptionPSK},
			}
			for _, f := range fields {
				if !equalHex(t, f.got, f.want) {
					t.Errorf("suite %#04x epoch %d: %s =\n  %x\nwant\n  %s",
						v.CipherSuite, i, f.name, f.got, f.want)
				}
				checked++
			}

			// The external public key must be the one derived from the external secret.
			pub, err := ExternalPub(got, suite)
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: ExternalPub: %v", v.CipherSuite, i, err)
			}
			if !equalHex(t, pub, e.ExternalPub) {
				t.Errorf("suite %#04x epoch %d: external_pub =\n  %x\nwant\n  %s",
					v.CipherSuite, i, pub, e.ExternalPub)
			}
			checked++

			// And the exporter must reproduce the vector's exported secret.
			exported, err := Export(got, e.Exporter.Label, mustHex(t, e.Exporter.Context), e.Exporter.Length, suite)
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: Export: %v", v.CipherSuite, i, err)
			}
			if !equalHex(t, exported, e.Exporter.Secret) {
				t.Errorf("suite %#04x epoch %d: exporter secret =\n  %x\nwant\n  %s",
					v.CipherSuite, i, exported, e.Exporter.Secret)
			}
			checked++

			initSecret = got.InitSecret
			epochs++
		}
	}

	if epochs == 0 {
		t.Fatal("no epoch was verified for an implemented cipher suite")
	}
	t.Logf("verified %d checks over %d epochs; skipped %d vectors for unimplemented suites",
		checked, epochs, unsupported)
}

// TestWhichJoinerVariantTheVectorsMean settles the one question that reading cannot.
//
// The chain can be implemented four ways — the two extraction orders crossed with binding
// the group context into the joiner secret or not — and every one of them is deterministic
// and self-consistent. This test runs all four against the first epoch of each vector and
// REPORTS which reproduces the published joiner secret, so that a mismatch in the test
// above is diagnosed in the same run rather than in a second round of guesswork.
func TestWhichJoinerVariantTheVectorsMean(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "key-schedule.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []keyScheduleVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("key-schedule.json is not valid JSON: %v", err)
	}

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			continue
		}
		if len(v.Epochs) == 0 {
			continue
		}

		e := v.Epochs[0]
		gc := GroupContext{
			Version:                 ProtocolVersion,
			CipherSuite:             v.CipherSuite,
			GroupID:                 mustHex(t, v.GroupID),
			Epoch:                   0,
			TreeHash:                mustHex(t, e.TreeHash),
			ConfirmedTranscriptHash: mustHex(t, e.ConfirmedTranscriptHash),
		}
		contextBytes, err := gc.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		initSecret := mustHex(t, v.InitialInitSecret)
		commitSecret := mustHex(t, e.CommitSecret)
		pskSecret := mustHex(t, e.PskSecret)
		wantJoiner := mustHex(t, e.JoinerSecret)
		wantWelcome := mustHex(t, e.WelcomeSecret)
		wantEpoch := mustHex(t, e.EncryptionSecret)

		for _, extractOrder := range []string{"Extract(init, commit)", "Extract(commit, init)"} {
			var extracted []byte
			if extractOrder == "Extract(init, commit)" {
				extracted, err = crypto.Extract(initSecret, commitSecret, suite)
			} else {
				extracted, err = crypto.Extract(commitSecret, initSecret, suite)
			}
			if err != nil {
				t.Fatal(err)
			}

			for _, joinerContext := range []string{"empty", "group_context"} {
				context := []byte(nil)
				if joinerContext == "group_context" {
					context = contextBytes
				}

				joiner, err := crypto.ExpandWithLabel(extracted, labelJoiner, context, suite.HashSize(), suite)
				if err != nil {
					t.Fatal(err)
				}
				if string(joiner) != string(wantJoiner) {
					continue
				}

				// The joiner secret matches; now determine the second extraction order by
				// seeing which one leads to the published welcome secret.
				for _, secondOrder := range []string{"Extract(joiner, psk)", "Extract(psk, joiner)"} {
					var intermediate []byte
					if secondOrder == "Extract(joiner, psk)" {
						intermediate, err = crypto.Extract(joiner, pskSecret, suite)
					} else {
						intermediate, err = crypto.Extract(pskSecret, joiner, suite)
					}
					if err != nil {
						t.Fatal(err)
					}

					welcome, err := crypto.DeriveSecret(intermediate, labelWelcome, suite)
					if err != nil {
						t.Fatal(err)
					}
					if string(welcome) != string(wantWelcome) {
						continue
					}

					epochSecret, err := crypto.ExpandWithLabel(intermediate, labelEpoch, contextBytes, suite.HashSize(), suite)
					if err != nil {
						t.Fatal(err)
					}
					_ = wantEpoch

					t.Logf("suite %#04x: the vectors mean  %s + joiner context = %s + %s",
						v.CipherSuite, extractOrder, joinerContext, secondOrder)
					if epochSecret == nil {
						t.Fatal("unreachable")
					}
					return
				}
			}
		}

		t.Errorf("suite %#04x: none of the four joiner variants and neither second-extraction "+
			"order reproduced the published secrets, so the chain is shaped differently than "+
			"this package assumes. The RFC text for section 8 is needed (the online copy "+
			"fetched during development truncated before it).", v.CipherSuite)
		return
	}
}
