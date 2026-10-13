package group

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/schedule"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Snapshotting an epoch, so that a group survives the process that created it.
//
// # Everything is hex inside a JSON object
//
// The binding has to hand this across the gomobile boundary, where the usable types are strings
// and byte slices; hex in JSON keeps one representation for the whole structure and lets the
// snapshot be inspected when something is wrong, which a packed binary blob would not.
//
// # The tree is stored in the format that was verified
//
// The ratchet tree is written with tree.MarshalTree — the `optional<Node>` vector that
// round-trips 98 official trees byte for byte. Re-encoding it here, even into another faithful
// form, would be a second encoder to keep correct, and the first one only works because the
// vectors check it.
//
// # What is NOT stored: the proposals
//
// The proposal cache is deliberately dropped. A cached proposal is only useful until the commit
// that cites it arrives; a snapshot taken across a restart would hold proposals for an epoch
// that has already moved on, and a commit citing them would be resolved against stale bytes.
// A member that restarts therefore needs the commit re-sent, which is the correct behaviour and
// is stated rather than silently half-supported.
//
// # What IS stored, and why the secrets are unavoidable
//
// The epoch's secrets must be stored: they cannot be recomputed from the tree, the context and
// the transcript alone without the init secret the epoch was derived from, and a member that
// forgot them would be unable to read anything it received after the restart.
//
// That is a real cost against section 9.2 — a secret that is kept is one that a compromise can
// reach — and the honest form of it is: a snapshot holds the epoch's keys, so it must be
// encrypted at rest by whoever stores it. The Android client does; this package says so and
// does not pretend the snapshot is safe to leave lying around.

// snapshotVersion is bumped whenever the layout changes. An older snapshot is REJECTED rather
// than migrated: a group whose keys were derived under a different layout is not something to
// guess about, and the same rule already applies to the one-to-one session snapshot.
const snapshotVersion = 1

type epochSnapshot struct {
	Version int    `json:"version"`
	Number  uint64 `json:"number"`
	Suite   uint16 `json:"suite"`

	Tree    string `json:"tree"`
	Context string `json:"context"`

	JoinerSecret       string `json:"joiner_secret"`
	WelcomeSecret      string `json:"welcome_secret"`
	InitSecret         string `json:"init_secret"`
	SenderDataSecret   string `json:"sender_data_secret"`
	EncryptionSecret   string `json:"encryption_secret"`
	ExporterSecret     string `json:"exporter_secret"`
	EpochAuthenticator string `json:"epoch_authenticator"`
	ExternalSecret     string `json:"external_secret"`
	ConfirmationKey    string `json:"confirmation_key"`
	MembershipKey      string `json:"membership_key"`
	ResumptionPSK      string `json:"resumption_psk"`

	ConfirmedTranscriptHash string `json:"confirmed_transcript_hash"`
	InterimTranscriptHash   string `json:"interim_transcript_hash"`

	// PrivateNodes is local private state, keyed by node index as a decimal string (JSON has no
	// integer keys). It is stored because losing it makes a member unable to follow any commit:
	// it could still send, and it would silently stop being able to receive.
	PrivateNodes map[string]string `json:"private_nodes,omitempty"`
}

// Snapshot serializes an epoch.
func (e *Epoch) Snapshot() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("mls/group: no epoch to snapshot")
	}

	treeBytes, err := tree.MarshalTree(e.Tree)
	if err != nil {
		return nil, fmt.Errorf("mls/group: encoding the ratchet tree: %w", err)
	}
	contextBytes, err := e.Context.Marshal()
	if err != nil {
		return nil, fmt.Errorf("mls/group: encoding the group context: %w", err)
	}

	s := epochSnapshot{
		Version: snapshotVersion,
		Number:  e.Number,
		Suite:   uint16(e.Suite),
		Tree:    hex.EncodeToString(treeBytes),
		Context: hex.EncodeToString(contextBytes),

		JoinerSecret:       hex.EncodeToString(e.Secrets.JoinerSecret),
		WelcomeSecret:      hex.EncodeToString(e.Secrets.WelcomeSecret),
		InitSecret:         hex.EncodeToString(e.Secrets.InitSecret),
		SenderDataSecret:   hex.EncodeToString(e.Secrets.SenderDataSecret),
		EncryptionSecret:   hex.EncodeToString(e.Secrets.EncryptionSecret),
		ExporterSecret:     hex.EncodeToString(e.Secrets.ExporterSecret),
		EpochAuthenticator: hex.EncodeToString(e.Secrets.EpochAuthenticator),
		ExternalSecret:     hex.EncodeToString(e.Secrets.ExternalSecret),
		ConfirmationKey:    hex.EncodeToString(e.Secrets.ConfirmationKey),
		MembershipKey:      hex.EncodeToString(e.Secrets.MembershipKey),
		ResumptionPSK:      hex.EncodeToString(e.Secrets.ResumptionPSK),

		ConfirmedTranscriptHash: hex.EncodeToString(e.Transcript.Confirmed),
		InterimTranscriptHash:   hex.EncodeToString(e.Transcript.Interim),
	}

	if len(e.PrivateNodes) > 0 {
		s.PrivateNodes = make(map[string]string, len(e.PrivateNodes))
		for node, key := range e.PrivateNodes {
			s.PrivateNodes[strconv.FormatUint(uint64(node), 10)] = hex.EncodeToString(key)
		}
	}

	return json.Marshal(s)
}

// RestoreEpoch rebuilds an epoch from a snapshot.
func RestoreEpoch(snapshot []byte) (*Epoch, error) {
	var s epochSnapshot
	if err := json.Unmarshal(snapshot, &s); err != nil {
		return nil, fmt.Errorf("mls/group: the snapshot is not valid JSON: %w", err)
	}
	if s.Version != snapshotVersion {
		return nil, fmt.Errorf("mls/group: the snapshot is version %d and this build writes %d; "+
			"an older snapshot is refused rather than migrated, because guessing at a group's "+
			"key material is not something to do quietly", s.Version, snapshotVersion)
	}

	treeBytes, err := hex.DecodeString(s.Tree)
	if err != nil {
		return nil, fmt.Errorf("mls/group: the tree is not hex: %w", err)
	}
	ratchet, err := tree.ParseTree(mlstls.NewReader(treeBytes))
	if err != nil {
		return nil, fmt.Errorf("mls/group: decoding the ratchet tree: %w", err)
	}

	contextBytes, err := hex.DecodeString(s.Context)
	if err != nil {
		return nil, fmt.Errorf("mls/group: the context is not hex: %w", err)
	}
	context, err := schedule.ParseGroupContextBytes(contextBytes)
	if err != nil {
		return nil, fmt.Errorf("mls/group: decoding the group context: %w", err)
	}

	decode := func(name, value string) ([]byte, error) {
		raw, err := hex.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("mls/group: %s is not hex: %w", name, err)
		}
		return raw, nil
	}

	secrets := schedule.EpochSecrets{}
	for _, field := range []struct {
		name   string
		value  string
		target *[]byte
	}{
		{"joiner_secret", s.JoinerSecret, &secrets.JoinerSecret},
		{"welcome_secret", s.WelcomeSecret, &secrets.WelcomeSecret},
		{"init_secret", s.InitSecret, &secrets.InitSecret},
		{"sender_data_secret", s.SenderDataSecret, &secrets.SenderDataSecret},
		{"encryption_secret", s.EncryptionSecret, &secrets.EncryptionSecret},
		{"exporter_secret", s.ExporterSecret, &secrets.ExporterSecret},
		{"epoch_authenticator", s.EpochAuthenticator, &secrets.EpochAuthenticator},
		{"external_secret", s.ExternalSecret, &secrets.ExternalSecret},
		{"confirmation_key", s.ConfirmationKey, &secrets.ConfirmationKey},
		{"membership_key", s.MembershipKey, &secrets.MembershipKey},
		{"resumption_psk", s.ResumptionPSK, &secrets.ResumptionPSK},
	} {
		raw, err := decode(field.name, field.value)
		if err != nil {
			return nil, err
		}
		*field.target = raw
	}

	confirmed, err := decode("confirmed_transcript_hash", s.ConfirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	interim, err := decode("interim_transcript_hash", s.InterimTranscriptHash)
	if err != nil {
		return nil, err
	}

	// The epoch's own consistency is checked here rather than left to the first message: a tree
	// that does not hash to what the context says would make every future signature and tag fail
	// for a reason that looks like a cryptographic problem and is not.
	privateNodes := make(map[uint32][]byte, len(s.PrivateNodes))
	for node, key := range s.PrivateNodes {
		index, err := strconv.ParseUint(node, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("mls/group: %q is not a node index: %w", node, err)
		}
		raw, err := decode("private node "+node, key)
		if err != nil {
			return nil, err
		}
		privateNodes[uint32(index)] = raw
	}

	restored := &Epoch{
		Number:     s.Number,
		Suite:      crypto.CipherSuite(s.Suite),
		Tree:       ratchet,
		Context:    context,
		Secrets:    secrets,
		Transcript: messages.Transcript{Confirmed: confirmed, Interim: interim},
		Proposals:  messages.NewProposalCache(crypto.CipherSuite(s.Suite)),

		PrivateNodes: privateNodes,
	}

	treeHash, err := treeHashOf(ratchet, restored.Suite)
	if err != nil {
		return nil, err
	}
	if len(context.TreeHash) > 0 && string(treeHash) != string(context.TreeHash) {
		return nil, fmt.Errorf("mls/group: the restored tree does not hash to the tree hash in the " +
			"restored context, so the snapshot is inconsistent")
	}
	if restored.Number != context.Epoch {
		return nil, fmt.Errorf("mls/group: the snapshot says epoch %d and its context says %d",
			restored.Number, context.Epoch)
	}

	return restored, nil
}
