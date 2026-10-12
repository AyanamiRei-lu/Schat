package messages

import (
	"bytes"
	"testing"
)

// These tests check the properties of the transcript chain that a plausible-looking but wrong
// implementation would break. There are no official vectors for it, so the evidence is the
// chain's own structure: what must change the result, and what must not.

// commitContent builds a commit for a given epoch without needing a *testing.T, so it can be
// called from anywhere in these tests. It deliberately does not reuse the shared sample
// proposal helper, which takes one.
func commitContent(epoch uint64) *FramedContent {
	return &FramedContent{
		GroupID: []byte("group"),
		Epoch:   epoch,
		Sender:  Sender{Type: SenderTypeMember, LeafIndex: 0},
		Type:    ContentTypeCommit,
		Commit: &Commit{Proposals: []*ProposalOrRef{
			{
				Type: ProposalOrRefTypeProposal,
				Proposal: &Proposal{
					Type:   ProposalTypeRemove,
					Remove: &Remove{Removed: 1},
				},
			},
		}},
	}
}

func TestTranscriptStartsEmptyAndIsNotAHashOfNothing(t *testing.T) {
	transcript := NewTranscript()

	if len(transcript.Confirmed) != 0 || len(transcript.Interim) != 0 {
		t.Fatal("a new group's transcript hashes must be the zero-length octet string")
	}

	advanced, err := transcript.Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest)
	if err != nil {
		t.Fatalf("Advance: %v", err)
	}

	if len(advanced.Confirmed) == 0 || len(advanced.Interim) == 0 {
		t.Fatal("advancing the transcript produced empty hashes")
	}
	if bytes.Equal(advanced.Confirmed, advanced.Interim) {
		t.Fatal("the confirmed and interim hashes are equal, so the confirmation tag is not " +
			"being folded into the chain")
	}

	// The receiver must be untouched: a caller that rejects the commit afterwards still has to
	// hold the epoch it was validating against.
	if len(transcript.Confirmed) != 0 || len(transcript.Interim) != 0 {
		t.Fatal("Advance modified the transcript it was called on")
	}
}

func TestTranscriptChainsAcrossEpochs(t *testing.T) {
	first, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature-1"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	second, err := first.Advance(WireFormatPublicMessage, commitContent(1),
		[]byte("signature-2"), bytes.Repeat([]byte{0x02}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first.Confirmed, second.Confirmed) {
		t.Fatal("the confirmed hash did not change between epochs")
	}

	// Order matters: advancing with the commits swapped must give a different result. Without
	// this check, an implementation that hashed the commits in a set rather than in sequence
	// would pass everything else.
	swapped, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature-2"), bytes.Repeat([]byte{0x02}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	swapped, err = swapped.Advance(WireFormatPublicMessage, commitContent(1),
		[]byte("signature-1"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(swapped.Confirmed, second.Confirmed) {
		t.Fatal("the transcript hash does not depend on the order of the commits")
	}
}

func TestTranscriptSeparatesTheConfirmedHashFromTheConfirmationTag(t *testing.T) {
	tagA := bytes.Repeat([]byte{0xAA}, 32)
	tagB := bytes.Repeat([]byte{0xBB}, 32)

	a, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature"), tagA, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature"), tagB, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	// The tag feeds the INTERIM hash only. If it leaked into the confirmed hash, the commit's
	// own signature — which covers the confirmed hash through the GroupContext — would depend
	// on the tag that is computed from it, and no commit could ever be produced.
	if !bytes.Equal(a.Confirmed, b.Confirmed) {
		t.Fatal("changing the confirmation tag changed the confirmed transcript hash, so the " +
			"tag is being folded in one step too early and a sender could not compute its own " +
			"signature")
	}
	if bytes.Equal(a.Interim, b.Interim) {
		t.Fatal("changing the confirmation tag did not change the interim transcript hash")
	}
}

func TestTranscriptCoversTheSignatureAndTheWireFormat(t *testing.T) {
	base, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	otherSignature, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("signature!"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.Confirmed, otherSignature.Confirmed) {
		t.Fatal("the commit's signature is not covered by the transcript hash")
	}

	otherFormat, err := NewTranscript().Advance(WireFormatPrivateMessage, commitContent(0),
		[]byte("signature"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.Confirmed, otherFormat.Confirmed) {
		t.Fatal("the wire format is not covered by the transcript hash")
	}
}

func TestTranscriptRefusesANonCommitAndAMissingTag(t *testing.T) {
	// A proposal cannot open an epoch.
	proposal := &FramedContent{
		GroupID: []byte("group"), Epoch: 0,
		Sender: Sender{Type: SenderTypeMember, LeafIndex: 0},
		Type:   ContentTypeProposal,
	}
	if _, err := NewTranscript().Advance(WireFormatPublicMessage, proposal,
		[]byte("sig"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest); err == nil {
		t.Fatal("a proposal was accepted as the commit that opens an epoch")
	}

	// An application message cannot either.
	application := &FramedContent{
		GroupID: []byte("group"), Epoch: 0,
		Sender:          Sender{Type: SenderTypeMember, LeafIndex: 0},
		Type:            ContentTypeApplication,
		ApplicationData: []byte("hi"),
	}
	if _, err := NewTranscript().Advance(WireFormatPublicMessage, application,
		[]byte("sig"), bytes.Repeat([]byte{0x01}, 32), suiteUnderTest); err == nil {
		t.Fatal("an application message was accepted as the commit that opens an epoch")
	}

	// And a commit with no confirmation tag has not confirmed anything.
	if _, err := NewTranscript().Advance(WireFormatPublicMessage, commitContent(0),
		[]byte("sig"), nil, suiteUnderTest); err == nil {
		t.Fatal("a commit with no confirmation tag advanced the transcript")
	}
}

func TestConfirmationTagDependsOnTheKeyAndTheHash(t *testing.T) {
	keyA := bytes.Repeat([]byte{0x11}, 32)
	keyB := bytes.Repeat([]byte{0x22}, 32)
	hashA := bytes.Repeat([]byte{0x33}, 32)
	hashB := bytes.Repeat([]byte{0x44}, 32)

	tag, err := ConfirmationTag(keyA, hashA, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if len(tag) == 0 {
		t.Fatal("the confirmation tag is empty")
	}

	again, err := ConfirmationTag(keyA, hashA, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tag, again) {
		t.Fatal("the confirmation tag is not deterministic")
	}

	otherKey, err := ConfirmationTag(keyB, hashA, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tag, otherKey) {
		t.Fatal("the confirmation tag does not depend on the key")
	}

	otherHash, err := ConfirmationTag(keyA, hashB, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tag, otherHash) {
		t.Fatal("the confirmation tag does not depend on the transcript hash")
	}

	if _, err := ConfirmationTag(nil, hashA, suiteUnderTest); err == nil {
		t.Fatal("a confirmation tag was produced with no key")
	}
}
