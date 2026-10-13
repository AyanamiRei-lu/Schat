package messages

import (
	"bytes"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// TestProposalReferenceMatchesTheSpecifiedConstruction pins the reference to the definition in
// the specification rather than to whatever this package happens to produce.
//
// The important part is the label. RefHash does not add the "MLS 1.0 " prefix — the caller
// supplies it — so a reference computed with "Proposal Reference" instead of
// "MLS 1.0 Proposal Reference" is self-consistent, reproducible, and interoperates with
// nothing. Recomputing it here from the primitive, with the label written out separately,
// means a change to the constant inside the package fails this test instead of silently
// changing every reference the implementation produces.
func TestProposalReferenceMatchesTheSpecifiedConstruction(t *testing.T) {
	proposal := sampleProposal(t, ProposalTypeRemove)

	got, err := MakeProposalReference(proposal, suiteUnderTest)
	if err != nil {
		t.Fatalf("MakeProposalReference: %v", err)
	}

	encoded, err := MarshalProposal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	want, err := crypto.RefHash("MLS 1.0 Proposal Reference", encoded, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("the reference is not RefHash(\"MLS 1.0 Proposal Reference\", proposal):\n"+
			"  got  %x\n  want %x", got, want)
	}

	// The prefix really is load-bearing: dropping it must produce a different value, otherwise
	// this test would pass even if the constant were wrong.
	withoutPrefix, err := crypto.RefHash("Proposal Reference", encoded, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, withoutPrefix) {
		t.Fatal("the reference does not depend on the label, so RefHash's label is being ignored")
	}

	// A different proposal must produce a different reference.
	other, err := MakeProposalReference(&Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 9}}, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, other) {
		t.Fatal("two different proposals share a reference")
	}
}

func TestProposalCacheIsBoundToItsEpoch(t *testing.T) {
	cache := NewProposalCache(suiteUnderTest)
	proposal := sampleProposal(t, ProposalTypeUpdate)

	ref, err := cache.Add(7, 3, proposal)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	found, err := cache.Lookup(7, ref)
	if err != nil {
		t.Fatalf("a proposal that was just cached could not be looked up: %v", err)
	}
	if found.Sender != 3 || found.Epoch != 7 {
		t.Fatalf("the cached entry lost its sender or epoch: %+v", found)
	}

	// The same reference must NOT resolve in another epoch. A reference is a hash of the
	// proposal alone, so nothing about it says which epoch it belongs to — the epoch has to
	// come from the cache key, and a lookup that ignored it would accept a proposal from an
	// epoch no honest sender could be citing here.
	if _, err := cache.Lookup(8, ref); err == nil {
		t.Fatal("a reference cached in epoch 7 resolved in epoch 8, so a proposal can be " +
			"carried across epochs by reference")
	}

	// Adding the same proposal again must not create a second entry or change the reference.
	again, err := cache.Add(7, 4, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ref, again) {
		t.Fatal("the same proposal produced two different references")
	}
	if cache.Len() != 1 {
		t.Fatalf("the cache holds %d entries after storing one proposal twice", cache.Len())
	}

	// And the first sender must not have been overwritten by the second.
	entry, err := cache.Lookup(7, ref)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Sender != 3 {
		t.Fatalf("a second Add replaced the cached entry's sender with %d", entry.Sender)
	}
}

func TestProposalCacheForgetsSpentEpochs(t *testing.T) {
	cache := NewProposalCache(suiteUnderTest)

	for epoch := uint64(0); epoch < 5; epoch++ {
		proposal := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: uint32(epoch)}}
		if _, err := cache.Add(epoch, 0, proposal); err != nil {
			t.Fatal(err)
		}
	}
	if cache.Len() != 5 {
		t.Fatalf("cached %d proposals, want 5", cache.Len())
	}

	// An unbounded cache is a denial-of-service target: anyone who can send a proposal can
	// make a member store one, so dropping spent epochs has to actually drop them.
	removed := cache.ForgetEpoch(3)
	if removed != 3 {
		t.Fatalf("ForgetEpoch(3) removed %d entries, want the three from epochs 0, 1 and 2", removed)
	}
	if cache.Len() != 2 {
		t.Fatalf("%d entries remain, want 2", cache.Len())
	}
}

func TestVerifyReferenceRejectsAMismatch(t *testing.T) {
	proposal := sampleProposal(t, ProposalTypeRemove)
	reference, err := MakeProposalReference(proposal, suiteUnderTest)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyReference(proposal, reference, suiteUnderTest); err != nil {
		t.Fatalf("a correct reference was rejected: %v", err)
	}

	// A reference to a different proposal must be refused. This is the check that stops a
	// sender from citing a reference that resolves to something other than what it claims.
	other := &Proposal{Type: ProposalTypeRemove, Remove: &Remove{Removed: 99}}
	if err := VerifyReference(other, reference, suiteUnderTest); err == nil {
		t.Fatal("a reference to one proposal was accepted for another")
	}

	// And a truncated or empty reference must not be accepted by accident.
	if err := VerifyReference(proposal, nil, suiteUnderTest); err == nil {
		t.Fatal("an empty reference was accepted")
	}
	if err := VerifyReference(proposal, reference[:len(reference)-1], suiteUnderTest); err == nil {
		t.Fatal("a truncated reference was accepted")
	}
}
