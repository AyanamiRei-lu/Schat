package mobile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Where the two members' transcripts first differ.
//
// A confirmation tag that does not match means the two sides computed different group state, and
// the transcript is one of the two inputs to that computation. Rather than reasoning about which
// step is wrong, this compares the value itself, at the moment both members are in the SAME
// epoch — immediately after one joined through a Welcome.
//
// That bisects the problem:
//
//   - if the transcripts already differ here, the fault is in joining (AcceptWelcome);
//   - if they agree here, the fault is in applying a commit (ProcessCommit).
//
// Three earlier attempts at this were reasoned rather than measured, and two of them changed
// code that was already correct.

// transcriptOf reads the two transcript hashes out of a group snapshot.
func transcriptOf(t *testing.T, stateJSON string) (confirmed, interim []byte) {
	t.Helper()

	var raw struct {
		Confirmed string `json:"confirmed_transcript_hash"`
		Interim   string `json:"interim_transcript_hash"`
	}
	if err := json.Unmarshal([]byte(stateJSON), &raw); err != nil {
		t.Fatalf("the snapshot is not valid JSON: %v", err)
	}

	confirmed, err := hex.DecodeString(raw.Confirmed)
	if err != nil {
		t.Fatalf("the confirmed transcript hash is not hex: %v", err)
	}
	interim, err = hex.DecodeString(raw.Interim)
	if err != nil {
		t.Fatalf("the interim transcript hash is not hex: %v", err)
	}
	return confirmed, interim
}

func TestTheJoiningMemberTranscriptMatchesTheGroup(t *testing.T) {
	_, _, aliceState, bobState := aliceAndState(t)

	aliceConfirmed, aliceInterim := transcriptOf(t, aliceState)
	bobConfirmed, bobInterim := transcriptOf(t, bobState)

	aliceSummary, err := GroupStateSummary(aliceState)
	if err != nil {
		t.Fatal(err)
	}
	bobSummary, err := GroupStateSummary(bobState)
	if err != nil {
		t.Fatal(err)
	}
	if aliceSummary.Epoch != bobSummary.Epoch {
		t.Fatalf("the two are not even in the same epoch: %d against %d",
			aliceSummary.Epoch, bobSummary.Epoch)
	}

	t.Logf("epoch %d", aliceSummary.Epoch)
	t.Logf("  committer confirmed = %x", aliceConfirmed)
	t.Logf("  joiner    confirmed = %x", bobConfirmed)
	t.Logf("  committer interim   = %x", aliceInterim)
	t.Logf("  joiner    interim   = %x", bobInterim)

	if !bytes.Equal(aliceConfirmed, bobConfirmed) {
		t.Fatal("the two disagree about the CONFIRMED transcript hash immediately after joining, " +
			"so the fault is in AcceptWelcome, not in applying a commit")
	}
	if !bytes.Equal(aliceInterim, bobInterim) {
		t.Fatal("the two agree about the confirmed transcript hash and disagree about the " +
			"INTERIM one, so the joining member's interim hash is wrong")
	}
}
