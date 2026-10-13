// Package schedule implements the MLS key schedule (RFC 9420 section 8).
//
// # What it does
//
// One epoch's shared state is derived from four inputs: the previous epoch's init secret,
// the commit secret produced by that epoch's TreeKEM update, an optional pre-shared key
// secret, and the group context. Everything a member needs in order to encrypt, decrypt,
// authenticate and prove membership is derived from the result.
//
// # Why the shape of the chain matters more than the labels
//
// The label table is easy: each derived secret has its own label and they are listed in
// section 8. What is not easy is the ORDER of the two extraction steps and what exactly is
// bound into each. The specification writes the chain as a diagram, and a reader can
// plausibly implement
//
//	Extract(init, commit)  or  Extract(commit, init)
//	ExpandWithLabel(., "joiner", "" ,  Nh)  or  ExpandWithLabel(., "joiner", GroupContext, Nh)
//
// and every one of those four combinations produces values that are deterministic,
// consistent with themselves and useless for interoperating with anybody. This project
// therefore does not guess: the test in this package tries each combination against the
// official key-schedule vectors and reports which one reproduces the published bytes. The
// answer is recorded in the code below, and the test fails loudly if it ever changes.
//
// # One subtlety worth stating
//
// The joiner secret is an input to the second extraction AND an output that is handed to a
// new member in a Welcome message. That makes it both an intermediate value and a
// published one, which is unusual for a key schedule and is why the derivation is written
// as two clearly separated steps here rather than as one expression.
package schedule

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// ProtocolVersion is the MLS protocol version this package implements (mls10).
const ProtocolVersion uint16 = 1

// Labels from RFC 9420 section 8, Table 4. Spelling matters: these strings are hashed.
const (
	labelJoiner         = "joiner"
	labelWelcome        = "welcome"
	labelEpoch          = "epoch"
	labelInit           = "init"
	labelSenderData     = "sender data"
	labelEncryption     = "encryption"
	labelExporter       = "exporter"
	labelAuthentication = "authentication"
	labelExternal       = "external"
	labelConfirmation   = "confirm"
	labelMembership     = "membership"
	labelResumption     = "resumption"
)

// GroupContext is the public state of a group in one epoch (RFC 9420 section 8.1).
//
// It is hashed into the key schedule, so any difference between two members' views of it
// produces two different epoch secrets — which is exactly the point: it binds the keys to
// the membership and the transcript they were negotiated under.
type GroupContext struct {
	Version                 uint16
	CipherSuite             uint16
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte

	// Extensions is the already-encoded Extension vector BODY (the elements, without the
	// vector's own length prefix). Kept as bytes because the extension types are not
	// needed until group creation, and encoding an empty one must still produce the
	// single zero byte the format requires.
	Extensions []byte
}

// Marshal encodes the group context.
//
// The layout was confirmed byte for byte against the official vectors before this was
// written: version and cipher suite as uint16, then group_id, tree_hash and
// confirmed_transcript_hash as variable-length vectors, then the epoch as a uint64, then
// the extension vector. Note that the epoch sits BETWEEN the group id and the hashes —
// easy to misread from the struct definition, since the field order in the struct and the
// order on the wire are the same but the vector lengths break the visual pattern.
func (g GroupContext) Marshal() ([]byte, error) {
	w := mlstls.NewWriter(2 + 2 + len(g.GroupID) + 8 + len(g.TreeHash) + len(g.ConfirmedTranscriptHash) + len(g.Extensions) + 4)

	w.Uint16(g.Version)
	w.Uint16(g.CipherSuite)
	w.Opaque(g.GroupID)
	w.Uint64(g.Epoch)
	w.Opaque(g.TreeHash)
	w.Opaque(g.ConfirmedTranscriptHash)
	w.Opaque(g.Extensions)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// EpochSecrets is everything one epoch's key schedule produces.
//
// Each field is derived from the epoch secret with its own label. They are kept as
// separate named fields rather than a map so that a caller cannot ask for a secret by a
// string it built itself: the label is a wire-visible constant, and a typo in a map key
// would silently produce a valid-looking secret that nothing else agrees with.
type EpochSecrets struct {
	JoinerSecret       []byte
	WelcomeSecret      []byte
	InitSecret         []byte
	SenderDataSecret   []byte
	EncryptionSecret   []byte
	ExporterSecret     []byte
	EpochAuthenticator []byte
	ExternalSecret     []byte
	ConfirmationKey    []byte
	MembershipKey      []byte
	ResumptionPSK      []byte
}

// KeySchedule derives one epoch's secrets.
//
//	intermediate     = KDF.Extract(init_secret, commit_secret)
//	joiner_secret    = ExpandWithLabel(intermediate, "joiner", GroupContext, KDF.Nh)
//	intermediate_psk = KDF.Extract(joiner_secret, psk_secret)
//	welcome_secret   = DeriveSecret(intermediate_psk, "welcome")
//	epoch_secret     = ExpandWithLabel(intermediate_psk, "epoch", GroupContext, KDF.Nh)
//
// The two things worth noticing are that the group context is bound into the joiner secret
// rather than only into the epoch secret, and that the extraction argument order is
// (previous secret as salt, new entropy as input keying material). Both were determined
// from the official vectors; see the package comment.
func KeySchedule(initSecret, commitSecret, pskSecret []byte, groupContext GroupContext, suite crypto.CipherSuite) (EpochSecrets, error) {
	var out EpochSecrets

	contextBytes, err := groupContext.Marshal()
	if err != nil {
		return out, fmt.Errorf("mls/schedule: encoding the group context: %w", err)
	}

	hashSize := suite.HashSize()
	if hashSize == 0 {
		return out, fmt.Errorf("mls/schedule: unsupported cipher suite %#04x", uint16(suite))
	}

	// Step 1: mix the commit secret into the previous epoch's init secret.
	extracted, err := crypto.Extract(initSecret, commitSecret, suite)
	if err != nil {
		return out, err
	}

	// Step 2: the joiner secret, with the group context bound in.
	out.JoinerSecret, err = crypto.ExpandWithLabel(extracted, labelJoiner, contextBytes, hashSize, suite)
	if err != nil {
		return out, err
	}

	// Step 3: mix in the PSK secret (the all-zero vector when there are no PSKs).
	intermediate, err := crypto.Extract(out.JoinerSecret, pskSecret, suite)
	if err != nil {
		return out, err
	}

	// Step 4: the welcome secret comes off before the epoch secret is derived, and only
	// from the intermediate value — it must not depend on the group context, because a
	// Welcome is built for a member who does not have the group's context yet.
	out.WelcomeSecret, err = crypto.DeriveSecret(intermediate, labelWelcome, suite)
	if err != nil {
		return out, err
	}

	// Step 5: the epoch secret, bound to the group context.
	epochSecret, err := crypto.ExpandWithLabel(intermediate, labelEpoch, contextBytes, hashSize, suite)
	if err != nil {
		return out, err
	}

	// Step 6: everything else, one label each.
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

// Export runs the MLS exporter (RFC 9420 section 8.5):
//
//	MLS-Exporter(Label, Context, Length) =
//	    DeriveSecret(exporter_secret, Label)
//	        |> ExpandWithLabel(., "exported", Hash(Context), Length)
//
// The context is HASHED rather than used directly, which is what lets an exporter call
// carry a structure of any size without changing the shape of what is signed into the key.
func Export(epoch EpochSecrets, label string, context []byte, length int, suite crypto.CipherSuite) ([]byte, error) {
	secret, err := crypto.DeriveSecret(epoch.ExporterSecret, label, suite)
	if err != nil {
		return nil, err
	}
	return crypto.ExpandWithLabel(secret, "exported", suite.Hash(context), length, suite)
}

// ExternalPub derives the public key published for external commits
// (RFC 9420 section 8.3): the private half is the external secret, and it is never sent.
func ExternalPub(epoch EpochSecrets, suite crypto.CipherSuite) ([]byte, error) {
	_, public, err := crypto.DeriveKeyPair(epoch.ExternalSecret, suite)
	if err != nil {
		return nil, err
	}
	return public, nil
}
