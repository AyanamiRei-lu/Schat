package schedule

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// SecretsFromEpochSecret, checked against the same official vectors that verify KeySchedule.
//
// The vector gives each epoch's joiner secret and PSK secret, which is enough to compute the
// epoch secret independently of this package:
//
//	intermediate = KDF.Extract(joiner_secret, psk_secret)
//	epoch_secret = ExpandWithLabel(intermediate, "epoch", GroupContext, KDF.Nh)
//
// so the test does not have to trust the code under test to produce its own input. Every
// labelled secret below the epoch secret is then compared against the published value.
//
// This is what group creation depends on: RFC 9420 section 11 has the creator choose the epoch
// secret directly, so the derivation from it has to be right on its own, without the chain that
// an ordinary epoch transition goes through.

func TestSecretsFromEpochSecretAgainstOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "vectors", "key-schedule.json"))
	if err != nil {
		t.Skipf("official MLS vectors are not present (%v); run tools/fetch-mls-vectors.ps1", err)
	}

	var vectors []keyScheduleVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("key-schedule.json is not valid JSON: %v", err)
	}

	checked, epochs, unsupported := 0, 0, 0

	for _, v := range vectors {
		suite := crypto.CipherSuite(v.CipherSuite)
		if _, err := suite.Params(); err != nil {
			unsupported++
			continue
		}

		groupID := mustHex(t, v.GroupID)

		for i, e := range v.Epochs {
			groupContext := GroupContext{
				Version:                 ProtocolVersion,
				CipherSuite:             v.CipherSuite,
				GroupID:                 groupID,
				Epoch:                   uint64(i),
				TreeHash:                mustHex(t, e.TreeHash),
				ConfirmedTranscriptHash: mustHex(t, e.ConfirmedTranscriptHash),
			}
			contextBytes, err := groupContext.Marshal()
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: %v", v.CipherSuite, i, err)
			}

			intermediate, err := crypto.Extract(mustHex(t, e.JoinerSecret), mustHex(t, e.PskSecret), suite)
			if err != nil {
				t.Fatal(err)
			}
			epochSecret, err := crypto.ExpandWithLabel(intermediate, labelEpoch, contextBytes, suite.HashSize(), suite)
			if err != nil {
				t.Fatal(err)
			}

			got, err := SecretsFromEpochSecret(epochSecret, suite)
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: SecretsFromEpochSecret: %v", v.CipherSuite, i, err)
			}

			fields := []struct {
				name string
				got  []byte
				want string
			}{
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

			// The two secrets a created group has not computed must stay empty rather than
			// being quietly filled with something derived: a caller that used them would be
			// building a Welcome from a value the specification never defines for this case.
			if len(got.JoinerSecret) != 0 || len(got.WelcomeSecret) != 0 {
				t.Errorf("suite %#04x epoch %d: the joiner and welcome secrets are populated (%d and "+
					"%d bytes) although creation does not derive them", v.CipherSuite, i,
					len(got.JoinerSecret), len(got.WelcomeSecret))
			}

			epochs++
		}
	}

	if epochs == 0 {
		t.Fatal("no epoch was checked for an implemented cipher suite")
	}
	if unsupported > 0 {
		t.Logf("skipped %d vectors for unimplemented cipher suites", unsupported)
	}
	t.Logf("verified %d labelled secrets derived from a supplied epoch secret, over %d epochs",
		checked, epochs)
}

// TestSecretsFromEpochSecretRejectsBadInput covers the two ways a caller can get this wrong:
// a suite with no hash, and an epoch secret of the wrong length — which would otherwise be
// hashed into a value that looks like a secret and is not the one anybody else computes.
func TestSecretsFromEpochSecretRejectsBadInput(t *testing.T) {
	if _, err := SecretsFromEpochSecret(make([]byte, 32), crypto.CipherSuite(0x00FF)); err == nil {
		t.Fatal("an unsupported cipher suite was accepted")
	}

	good := make([]byte, suiteForTests().HashSize())
	if _, err := SecretsFromEpochSecret(good, suiteForTests()); err != nil {
		t.Fatalf("a correct epoch secret was rejected: %v", err)
	}

	for _, length := range []int{0, 16, 31, 33, 64} {
		if length == suiteForTests().HashSize() {
			continue
		}
		if _, err := SecretsFromEpochSecret(make([]byte, length), suiteForTests()); err == nil {
			t.Fatalf("an epoch secret of %d bytes was accepted for a suite whose hash is %d bytes",
				length, suiteForTests().HashSize())
		}
	}
}

func suiteForTests() crypto.CipherSuite { return crypto.CipherSuite(0x0001) }
