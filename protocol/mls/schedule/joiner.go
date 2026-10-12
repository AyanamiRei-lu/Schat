package schedule

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
)

// Deriving an epoch's secrets from the joiner secret (RFC 9420 sections 8.1 and 12.4.3.1).
//
// # Why a joined member needs its own entry point
//
// KeySchedule starts by extracting the commit secret into the previous epoch's init secret.
// A member that joined through a Welcome has NEITHER: it was not in the previous epoch, so it
// has no init secret, and it did not receive the commit, so it has no commit secret. What it
// has is the joiner secret, handed to it in the Welcome, and the key schedule's chain from
// there is the second half of the same diagram:
//
//	intermediate   = KDF.Extract(joiner_secret, psk_secret)
//	welcome_secret = DeriveSecret(intermediate, "welcome")
//	epoch_secret   = ExpandWithLabel(intermediate, "epoch", GroupContext, KDF.Nh)
//
// and then one labelled DeriveSecret per secret below that.
//
// # The welcome secret, and the order it forces
//
// The welcome secret is returned rather than discarded because it is what decrypts the
// GroupInfo — and the GroupInfo is where the GroupContext comes from. So a joiner's order is:
//
//	joiner secret + PSKs  ->  welcome secret  ->  key and nonce  ->  GroupInfo  ->  GroupContext
//	                      ->  epoch secret    ->  the epoch's other secrets
//
// The epoch secret cannot be computed first, and an implementation that tried would find it
// had no GroupContext to bind it to. That is the specification's order, not a preference.

// SecretsFromJoinerSecret derives an epoch's secrets for a member that received a Welcome.
//
// It returns the secrets and, separately, the welcome secret, which is needed to decrypt the
// GroupInfo before the epoch secret can be computed at all.
func SecretsFromJoinerSecret(
	joinerSecret, pskSecret []byte,
	groupContext GroupContext,
	suite crypto.CipherSuite,
) (EpochSecrets, []byte, error) {
	var out EpochSecrets

	hashSize := suite.HashSize()
	if hashSize == 0 {
		return out, nil, fmt.Errorf("mls/schedule: unsupported cipher suite %#04x", uint16(suite))
	}
	if len(joinerSecret) != hashSize {
		return out, nil, fmt.Errorf("mls/schedule: the joiner secret is %d bytes, want %d",
			len(joinerSecret), hashSize)
	}
	if len(pskSecret) != hashSize {
		return out, nil, fmt.Errorf("mls/schedule: the PSK secret is %d bytes, want %d",
			len(pskSecret), hashSize)
	}

	contextBytes, err := groupContext.Marshal()
	if err != nil {
		return out, nil, fmt.Errorf("mls/schedule: encoding the group context: %w", err)
	}

	out.JoinerSecret = joinerSecret

	intermediate, err := crypto.Extract(joinerSecret, pskSecret, suite)
	if err != nil {
		return out, nil, err
	}

	welcomeSecret, err := deriveWelcomeSecret(intermediate, suite)
	if err != nil {
		return out, nil, err
	}

	epochSecret, err := crypto.ExpandWithLabel(intermediate, labelEpoch, contextBytes, hashSize, suite)
	if err != nil {
		return out, nil, err
	}

	if out, err = secretsBelowEpochSecret(epochSecret, suite); err != nil {
		return EpochSecrets{}, nil, err
	}
	out.JoinerSecret = joinerSecret

	return out, welcomeSecret, nil
}

// secretsBelowEpochSecret derives everything that hangs off the epoch secret.
//
// Shared with SecretsFromEpochSecret so that a created group and a joined member cannot end up
// with two different sets of labels: the labels are wire-visible constants, and a divergence
// there would produce secrets that are internally consistent and agreed with by nobody.
func secretsBelowEpochSecret(epochSecret []byte, suite crypto.CipherSuite) (EpochSecrets, error) {
	return SecretsFromEpochSecret(epochSecret, suite)
}

// WelcomeSecretFromJoiner derives just the welcome secret, which a joiner needs BEFORE it has a
// GroupContext.
//
// The order is forced: the group context lives inside the GroupInfo, the GroupInfo is encrypted
// under the welcome key, and the welcome secret is derived from the joiner secret and the PSK
// secret alone. So a joiner computes this first, decrypts the GroupInfo, and only then has a
// context to run SecretsFromJoinerSecret with. An implementation that tried to do everything in
// one call would need a context it cannot have yet.
func WelcomeSecretFromJoiner(joinerSecret, pskSecret []byte, suite crypto.CipherSuite) ([]byte, error) {
	hashSize := suite.HashSize()
	if hashSize == 0 {
		return nil, fmt.Errorf("mls/schedule: unsupported cipher suite %#04x", uint16(suite))
	}
	if len(joinerSecret) != hashSize {
		return nil, fmt.Errorf("mls/schedule: the joiner secret is %d bytes, want %d",
			len(joinerSecret), hashSize)
	}
	if len(pskSecret) != hashSize {
		return nil, fmt.Errorf("mls/schedule: the PSK secret is %d bytes, want %d",
			len(pskSecret), hashSize)
	}

	intermediate, err := crypto.Extract(joinerSecret, pskSecret, suite)
	if err != nil {
		return nil, err
	}
	return deriveWelcomeSecret(intermediate, suite)
}

// deriveWelcomeSecret is the one place the welcome secret is computed, so that a joiner's two
// paths to it cannot drift apart.
func deriveWelcomeSecret(intermediate []byte, suite crypto.CipherSuite) ([]byte, error) {
	return crypto.DeriveSecret(intermediate, labelWelcome, suite)
}
