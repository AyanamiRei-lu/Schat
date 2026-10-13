package schedule

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// The joiner's derivation, checked against the official key-schedule vectors.
//
// This is the one part of the joiner's path that CAN be checked byte for byte: the vectors
// publish the joiner secret and the PSK secret as inputs and every derived value as output, so
// the second half of the key schedule is verified without needing a Welcome, a GroupInfo or a
// ratchet tree. The parts that no vector covers — the Welcome's encryption, the lowest common
// ancestor — are tested separately and cannot be checked this way.

func TestSecretsFromJoinerSecretAgainstOfficialVectors(t *testing.T) {
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

			got, welcomeSecret, err := SecretsFromJoinerSecret(
				mustHex(t, e.JoinerSecret), mustHex(t, e.PskSecret), groupContext, suite)
			if err != nil {
				t.Fatalf("suite %#04x epoch %d: SecretsFromJoinerSecret: %v", v.CipherSuite, i, err)
			}

			fields := []struct {
				name string
				got  []byte
				want string
			}{
				// The welcome secret comes first because it is what a joiner needs before it has
				// a GroupContext at all: it is the key to the GroupInfo that carries one.
				{"welcome_secret", welcomeSecret, e.WelcomeSecret},
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

			if !equalHex(t, got.JoinerSecret, e.JoinerSecret) {
				t.Errorf("suite %#04x epoch %d: the joiner secret was not carried through", v.CipherSuite, i)
			}
			checked++

			epochs++
		}
	}

	if epochs == 0 {
		t.Fatal("no epoch was checked for an implemented cipher suite")
	}
	if unsupported > 0 {
		t.Logf("skipped %d vectors for unimplemented cipher suites", unsupported)
	}
	t.Logf("verified %d values derived from the joiner secret, over %d epochs", checked, epochs)
}

func TestSecretsFromJoinerSecretRejectsBadInput(t *testing.T) {
	suite := suiteForTests()
	good := make([]byte, suite.HashSize())
	ctx := GroupContext{Version: ProtocolVersion, CipherSuite: uint16(suite), GroupID: []byte("g")}

	if _, _, err := SecretsFromJoinerSecret(make([]byte, 8), good, ctx, suite); err == nil {
		t.Fatal("a joiner secret of the wrong length was accepted")
	}
	if _, _, err := SecretsFromJoinerSecret(good, make([]byte, 8), ctx, suite); err == nil {
		t.Fatal("a PSK secret of the wrong length was accepted")
	}
	if _, _, err := SecretsFromJoinerSecret(good, good, ctx, crypto.CipherSuite(0x00FF)); err == nil {
		t.Fatal("an unsupported cipher suite was accepted")
	}
	if _, _, err := SecretsFromJoinerSecret(good, good, ctx, suite); err != nil {
		t.Fatalf("a correct call failed: %v", err)
	}
}
