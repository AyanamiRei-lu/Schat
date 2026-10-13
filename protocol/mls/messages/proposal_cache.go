package messages

import (
	"bytes"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// Proposal references and the proposal cache (RFC 9420 sections 5.2 and 12.4).
//
// # What a ProposalRef actually is
//
//	MakeProposalRef(value) = RefHash("MLS 1.0 Proposal Reference", value)
//
//	struct { opaque label<V>; opaque value<V>; } RefHashInput;
//
// It is a plain labelled hash. It is NOT a MAC, it carries no key, and any party that can see
// a proposal can compute its reference. An earlier comment in this package claimed otherwise
// — that the reference was a MAC under the epoch's membership key, so that only members could
// produce one and one could not be replayed across epochs. Every part of that was invented,
// and it is the kind of invention that misleads: a reader who believed it would treat a
// reference as authenticated and stop checking the proposal it points at.
//
// The label includes the literal "MLS 1.0 " prefix, and RefHash does not add it — the caller
// supplies the whole string, which is why it is written out here in full rather than composed.
//
// # Why the cache exists
//
// A commit refers to proposals by reference as often as by value, so a receiver must have
// kept the proposals it was sent earlier or it cannot process the commit at all. The
// specification requires them to be stored by hash for exactly this reason.
//
// The cache is deliberately not a map that accepts anything: entries are keyed by the
// reference AND the epoch they were made in, because the same proposal sent in two epochs is
// two different references, and a cache that ignored the epoch would let a proposal from an
// old epoch satisfy a commit in a new one.

// MakeProposalReference computes the reference for a proposal.
func MakeProposalReference(p *Proposal, suite crypto.CipherSuite) (ProposalRef, error) {
	encoded, err := MarshalProposal(p)
	if err != nil {
		return nil, err
	}
	digest, err := crypto.RefHash("MLS 1.0 Proposal Reference", encoded, suite)
	if err != nil {
		return nil, err
	}
	return ProposalRef(digest), nil
}

// CachedProposal is a stored proposal together with what is needed to judge it later.
type CachedProposal struct {
	Reference ProposalRef
	Epoch     uint64
	Sender    uint32 // the proposer's leaf index
	Proposal  *Proposal
}

// ProposalCache stores proposals by reference, per epoch.
type ProposalCache struct {
	entries map[string]CachedProposal
	suite   crypto.CipherSuite
}

// NewProposalCache creates an empty cache for one cipher suite.
func NewProposalCache(suite crypto.CipherSuite) *ProposalCache {
	return &ProposalCache{entries: map[string]CachedProposal{}, suite: suite}
}

func cacheKey(epoch uint64, ref ProposalRef) string {
	var epochBytes [8]byte
	for i := 0; i < 8; i++ {
		epochBytes[i] = byte(epoch >> (8 * (7 - i)))
	}
	return string(epochBytes[:]) + string(ref)
}

// Add stores a proposal and returns the reference a commit would use to cite it.
//
// Storing the same proposal twice is not an error: two members may both forward it, and the
// reference is a function of the bytes, so both produce the same key. The second store is a
// no-op rather than an overwrite, so that a caller cannot replace a cached proposal with a
// different one under the same reference — which the hash makes impossible anyway, but the
// code should not depend on that to be safe.
func (c *ProposalCache) Add(epoch uint64, sender uint32, p *Proposal) (ProposalRef, error) {
	ref, err := MakeProposalReference(p, c.suite)
	if err != nil {
		return nil, err
	}

	key := cacheKey(epoch, ref)
	if _, exists := c.entries[key]; !exists {
		c.entries[key] = CachedProposal{
			Reference: ref,
			Epoch:     epoch,
			Sender:    sender,
			Proposal:  p,
		}
	}
	return ref, nil
}

// Lookup returns a cached proposal.
//
// The epoch is part of the key rather than checked afterwards: a proposal made in an earlier
// epoch has a different reference, so a commit in this epoch cannot legitimately cite it, and
// a lookup that searched across epochs would accept one that no honest sender could have
// produced.
func (c *ProposalCache) Lookup(epoch uint64, ref ProposalRef) (*CachedProposal, error) {
	entry, ok := c.entries[cacheKey(epoch, ref)]
	if !ok {
		return nil, fmt.Errorf("mls/messages: no cached proposal for this reference in epoch %d", epoch)
	}
	return &entry, nil
}

// Len reports how many proposals are cached, across all epochs.
func (c *ProposalCache) Len() int { return len(c.entries) }

// ForgetEpoch drops the proposals cached for epochs below the given one.
//
// Called when a commit is accepted: the proposals it applied are spent, and keeping them
// costs memory for no benefit. The bound matters more than the tidiness — an unbounded cache
// is a denial-of-service target, since anyone who can send a proposal can make a member
// store one.
func (c *ProposalCache) ForgetEpoch(below uint64) int {
	removed := 0
	for key, entry := range c.entries {
		if entry.Epoch < below {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

// VerifyReference checks that a reference in a commit really identifies the proposal it is
// being used for.
//
// This exists because a reference is unauthenticated: a commit carries the reference, and
// nothing in the reference itself says which proposal it came from. A receiver that looked up
// the cached proposal and applied it WITHOUT this check would apply whatever the cache
// happened to hold under a colliding key — and since the sender chooses the reference, that
// is a sender-controlled choice.
func VerifyReference(p *Proposal, ref ProposalRef, suite crypto.CipherSuite) error {
	computed, err := MakeProposalReference(p, suite)
	if err != nil {
		return err
	}
	if !bytes.Equal(computed, ref) {
		return fmt.Errorf("mls/messages: the proposal's reference is\n  %x\nbut the commit cites\n  %x",
			computed, ref)
	}
	return nil
}
