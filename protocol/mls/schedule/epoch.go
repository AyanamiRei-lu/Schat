package schedule

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// Deriving an epoch's secrets from a GIVEN epoch secret.
//
// # Why this entry point exists separately from KeySchedule
//
// KeySchedule derives the epoch secret from the init secret, the commit secret and the PSK
// secret — the chain an existing group follows when it moves to a new epoch.
//
// Group creation does not follow that chain. RFC 9420 section 11 requires the creator to
// initialize a one-member group with "Epoch secret: A fresh random value of size KDF.Nh", so
// the epoch secret is an INPUT there rather than an output. Running it through KeySchedule
// would mean inventing an init secret and a commit secret that the specification never
// mentions, and the resulting group would agree with itself and with nothing else.
//
// The two entry points meet at the same place: everything below the epoch secret is derived
// with one labelled DeriveSecret each, and that is all this function does.
//
// # What is NOT set
//
// JoinerSecret and WelcomeSecret are left empty. They are produced by the chain that creation
// skips: the joiner secret is what a Welcome hands to a new member, and a group that was just
// created has nobody to welcome. A caller that found them empty and used them anyway would be
// building a Welcome for the first epoch from a value that was never computed, which this
// function cannot prevent but can at least document.

// SecretsFromEpochSecret derives the epoch's sub-secrets from an epoch secret the caller
// supplies.
func SecretsFromEpochSecret(epochSecret []byte, suite crypto.CipherSuite) (EpochSecrets, error) {
	var out EpochSecrets

	hashSize := suite.HashSize()
	if hashSize == 0 {
		return out, fmt.Errorf("mls/schedule: unsupported cipher suite %#04x", uint16(suite))
	}
	if len(epochSecret) != hashSize {
		return out, fmt.Errorf("mls/schedule: the epoch secret is %d bytes, want %d",
			len(epochSecret), hashSize)
	}

	derived := []struct {
		label  string
		target *[]byte
	}{
		{labelInit, &out.InitSecret},
		{labelSenderData, &out.SenderDataSecret},
		{labelEncryption, &out.EncryptionSecret},
		{labelExporter, &out.ExporterSecret},
		{labelAuthentication, &out.EpochAuthenticator},
		{labelExternal, &out.ExternalSecret},
		{labelConfirmation, &out.ConfirmationKey},
		{labelMembership, &out.MembershipKey},
		{labelResumption, &out.ResumptionPSK},
	}

	for _, d := range derived {
		value, err := crypto.DeriveSecret(epochSecret, d.label, suite)
		if err != nil {
			return out, fmt.Errorf("mls/schedule: deriving %q: %w", d.label, err)
		}
		*d.target = value
	}

	return out, nil
}
