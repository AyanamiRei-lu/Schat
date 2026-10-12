package group

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/schat/schat/protocol/mls/messages"
	"github.com/schat/schat/protocol/mls/schedule"
	"github.com/schat/schat/protocol/mls/secrettree"
)

// Snapshotting and restoring an epoch.
//
// The property that matters is not that the fields come back — it is that a group which was
// restored can still talk to members that were never interrupted. A snapshot that restored
// every field a test thought to compare, and still produced a secret tree nobody else agrees
// with, would pass a field-by-field check and fail in use.

func TestSnapshotRestoresAnEpochThatStillInteroperates(t *testing.T) {
	f := twoMemberGroup(t)

	snapshot, err := f.epoch.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	restored, err := RestoreEpoch(snapshot)
	if err != nil {
		t.Fatalf("RestoreEpoch: %v", err)
	}

	if restored.Number != f.epoch.Number {
		t.Fatalf("the epoch number came back as %d, want %d", restored.Number, f.epoch.Number)
	}
	if restored.Suite != f.epoch.Suite {
		t.Fatal("the cipher suite did not survive")
	}

	for name, pair := range map[string][2][]byte{
		"init secret":         {restored.Secrets.InitSecret, f.epoch.Secrets.InitSecret},
		"encryption secret":   {restored.Secrets.EncryptionSecret, f.epoch.Secrets.EncryptionSecret},
		"confirmation key":    {restored.Secrets.ConfirmationKey, f.epoch.Secrets.ConfirmationKey},
		"membership key":      {restored.Secrets.MembershipKey, f.epoch.Secrets.MembershipKey},
		"sender data secret":  {restored.Secrets.SenderDataSecret, f.epoch.Secrets.SenderDataSecret},
		"epoch authenticator": {restored.Secrets.EpochAuthenticator, f.epoch.Secrets.EpochAuthenticator},
		"exporter secret":     {restored.Secrets.ExporterSecret, f.epoch.Secrets.ExporterSecret},
		"interim transcript":  {restored.Transcript.Interim, f.epoch.Transcript.Interim},
	} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("the restored %s differs from the original", name)
		}
	}

	// The property a field comparison cannot give: a message sealed by the ORIGINAL epoch opens
	// under the RESTORED one, each side building its own secret tree.
	originalTree, err := secrettree.New(f.epoch.Secrets.EncryptionSecret, 2, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := originalTree.ApplicationRatchet(0)
	if err != nil {
		t.Fatal(err)
	}

	senderDataKey := bytes.Repeat([]byte{0x31}, suiteUnderTest.HashSize())

	sealed, err := SealApplication(SealApplicationInput{
		GroupID: f.epoch.Context.GroupID, Epoch: f.epoch.Number,
		Ratchet:          ratchet,
		SenderData:       messages.SenderData{LeafIndex: 0, Generation: 0},
		SenderDataSecret: senderDataKey,
		Plaintext:        []byte("a message long enough for the sample"), Seal: stdAESSeal,
	})
	if err != nil {
		t.Fatalf("SealApplication: %v", err)
	}

	restoredTree, err := secrettree.New(restored.Secrets.EncryptionSecret, 2, suiteUnderTest)
	if err != nil {
		t.Fatalf("the restored epoch cannot build a secret tree: %v", err)
	}

	opened, err := OpenApplication(OpenApplicationInput{
		Message: sealed, ExpectedEpoch: restored.Number, ExpectedGroupID: restored.Context.GroupID,
		Tree: restoredTree, SenderDataSecret: senderDataKey,
		Open: stdAESOpen,
	})
	if err != nil {
		t.Fatalf("a restored epoch could not read a message from the original: %v", err)
	}
	if string(opened.Plaintext) != "a message long enough for the sample" {
		t.Fatalf("the restored epoch read %q", opened.Plaintext)
	}

	// Snapshotting the restored epoch must give the same bytes: state may not drift across a
	// save and load, or a group would change every time the app restarted.
	second, err := restored.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, second) {
		t.Fatal("snapshotting a restored epoch produced different bytes, so state drifts across " +
			"a restart")
	}
}

func TestRestoreRejectsWhatItMust(t *testing.T) {
	f := twoMemberGroup(t)
	good, err := f.epoch.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreEpoch([]byte("not json")); err == nil {
		t.Fatal("garbage was accepted as a snapshot")
	}

	var s epochSnapshot
	if err := json.Unmarshal(good, &s); err != nil {
		t.Fatal(err)
	}

	// An older version: refused, not migrated.
	s.Version = 0
	if _, err := RestoreEpoch(mustJSON(t, s)); err == nil {
		t.Fatal("a snapshot from an older version was accepted")
	}
	s.Version = snapshotVersion

	// A context whose TREE HASH was changed in place. The tree hash is a field inside the
	// encoded context, so it has to be edited through the codec: appending or truncating bytes
	// at the end of that encoding edits the trailing extensions field instead and leaves the
	// tree hash untouched, which is what an earlier version of this test did — and it then
	// reported the implementation as too permissive when the implementation was right.
	rawContext, err := hex.DecodeString(s.Context)
	if err != nil {
		t.Fatal(err)
	}
	context, err := schedule.ParseGroupContextBytes(rawContext)
	if err != nil {
		t.Fatal(err)
	}
	context.TreeHash = append([]byte(nil), context.TreeHash...)
	context.TreeHash[0] ^= 0x01
	reserialized, err := context.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s.Context = hex.EncodeToString(reserialized)
	if _, err := RestoreEpoch(mustJSON(t, s)); err == nil {
		t.Fatal("a snapshot whose tree does not match its context was accepted")
	}

	// An epoch number that disagrees with the context.
	var other epochSnapshot
	if err := json.Unmarshal(good, &other); err != nil {
		t.Fatal(err)
	}
	other.Number = 99
	if _, err := RestoreEpoch(mustJSON(t, other)); err == nil {
		t.Fatal("a snapshot whose epoch number disagrees with its context was accepted")
	}

	// A secret that is not hex.
	var third epochSnapshot
	if err := json.Unmarshal(good, &third); err != nil {
		t.Fatal(err)
	}
	third.EncryptionSecret = "zz"
	if _, err := RestoreEpoch(mustJSON(t, third)); err == nil {
		t.Fatal("a snapshot with a non-hex secret was accepted")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
