// Package messages implements the MLS message layer: proposals, commits and the framing
// they travel in (RFC 9420 sections 12 and 6).
//
// # Where the structures in this package come from
//
// Every field order, every enum width and every label here was read from the specification
// text before being written, not recalled. That is not a stylistic preference: across the
// earlier milestones of this project, every single value written from memory turned out to
// be wrong — the HKDF expansion, the joiner secret's context, the root node's index, whether
// a parent hash is blanked, the PSK label — and every one of them was corrected only by
// reading the text or by a vector. The habit is kept here.
//
// # What is implemented, and what refuses to be
//
// Update and Remove are complete, because their bodies are a LeafNode and a leaf index, both
// of which this project already encodes and has verified.
//
// Add is not: it carries a KeyPackage, which is M5's subject and has not been written yet.
// Its wire form is not guessed at. A proposal that cannot be encoded correctly returns an
// error naming what is missing, which is strictly more useful than bytes that look right and
// are not.
package messages

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// ProposalType is a two-byte enum: its values end at (0xffff).
type ProposalType uint16

const (
	ProposalTypeReserved               ProposalType = 0
	ProposalTypeAdd                    ProposalType = 1
	ProposalTypeUpdate                 ProposalType = 2
	ProposalTypeRemove                 ProposalType = 3
	ProposalTypePSK                    ProposalType = 4
	ProposalTypeReInit                 ProposalType = 5
	ProposalTypeExternalInit           ProposalType = 6
	ProposalTypeGroupContextExtensions ProposalType = 7
)

// ProposalOrRefType is a one-byte enum: its values end at (255).
type ProposalOrRefType uint8

const (
	ProposalOrRefTypeReserved  ProposalOrRefType = 0
	ProposalOrRefTypeProposal  ProposalOrRefType = 1
	ProposalOrRefTypeReference ProposalOrRefType = 2
)

// ErrNotImplementedYet marks a structure this package refuses to encode rather than guess.
type ErrNotImplementedYet struct{ What string }

func (e ErrNotImplementedYet) Error() string {
	return "mls/messages: not implemented yet: " + e.What
}

// Proposal is one change to the group, inline in a commit or cached by reference.
type Proposal struct {
	Type ProposalType

	// Update carries the sender's new leaf node.
	Update *Update

	// Remove carries the LEAF index of the member being removed — not the node index.
	Remove *Remove

	// Add carries the KeyPackage of the member being added. The leaf index the member will
	// occupy is decided by the commit that applies it, not by the proposal: a proposal says
	// WHO, and the committer decides WHERE.
	Add *Add
}

// Add is a request to add the member described by a KeyPackage.
type Add struct {
	KeyPackage *KeyPackage
}

// Update is a member replacing its own leaf node.
type Update struct {
	LeafNode *tree.LeafNode
}

// Remove is a request to remove the member at a leaf index.
type Remove struct {
	Removed uint32
}

// ProposalRef identifies a proposal that was sent earlier and is cached by hash.
//
// It is a plain labelled hash — MakeProposalRef(value) = RefHash("MLS 1.0 Proposal
// Reference", value) — and NOT a MAC. An earlier version of this comment claimed it was a
// MAC under the epoch's membership key, which would mean only members could produce one and
// that one could not be replayed across epochs. None of that is true, and the claim was
// dangerous rather than merely wrong: a reader who believed it would treat a reference as
// authenticated and stop checking the proposal it points at. See proposal_cache.go, which
// computes it and which explains why VerifyReference exists.
type ProposalRef []byte

// ProposalOrRef is either a proposal itself or a reference to one sent earlier.
type ProposalOrRef struct {
	Type      ProposalOrRefType
	Proposal  *Proposal
	Reference ProposalRef
}

// ParseProposal decodes a Proposal.
func ParseProposal(r *mlstls.Reader) (*Proposal, error) {
	rawType, err := r.Uint16()
	if err != nil {
		return nil, err
	}

	out := &Proposal{Type: ProposalType(rawType)}

	switch out.Type {
	case ProposalTypeUpdate:
		leaf, err := parseLeafNodeFrom(r)
		if err != nil {
			return nil, err
		}
		out.Update = &Update{LeafNode: leaf}

	case ProposalTypeRemove:
		removed, err := r.Uint32()
		if err != nil {
			return nil, err
		}
		out.Remove = &Remove{Removed: removed}

	case ProposalTypeAdd:
		keyPackage, err := ParseKeyPackage(r)
		if err != nil {
			return nil, err
		}
		out.Add = &Add{KeyPackage: keyPackage}

	default:
		return nil, ErrNotImplementedYet{What: fmt.Sprintf("proposal type %d", rawType)}
	}

	return out, nil
}

// Marshal encodes a proposal.
func (p *Proposal) Marshal(w *mlstls.Writer) error {
	w.Uint16(uint16(p.Type))

	switch p.Type {
	case ProposalTypeUpdate:
		if p.Update == nil || p.Update.LeafNode == nil {
			return fmt.Errorf("mls/messages: an Update proposal with no leaf node")
		}
		return p.Update.LeafNode.MarshalTo(w)

	case ProposalTypeRemove:
		if p.Remove == nil {
			return fmt.Errorf("mls/messages: a Remove proposal with no leaf index")
		}
		w.Uint32(p.Remove.Removed)
		return nil

	case ProposalTypeAdd:
		if p.Add == nil || p.Add.KeyPackage == nil {
			return fmt.Errorf("mls/messages: an Add proposal with no KeyPackage")
		}
		return p.Add.KeyPackage.Marshal(w)

	default:
		return ErrNotImplementedYet{What: fmt.Sprintf("proposal type %d", p.Type)}
	}
}

// MarshalProposal encodes a proposal and returns the bytes.
func MarshalProposal(p *Proposal) ([]byte, error) {
	w := mlstls.NewWriter(256)
	if err := p.Marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// ParseProposalOrRef decodes a ProposalOrRef.
func ParseProposalOrRef(r *mlstls.Reader) (*ProposalOrRef, error) {
	rawType, err := r.Uint8()
	if err != nil {
		return nil, err
	}

	out := &ProposalOrRef{Type: ProposalOrRefType(rawType)}

	switch out.Type {
	case ProposalOrRefTypeProposal:
		proposal, err := ParseProposal(r)
		if err != nil {
			return nil, err
		}
		out.Proposal = proposal

	case ProposalOrRefTypeReference:
		ref, err := r.Opaque()
		if err != nil {
			return nil, err
		}
		out.Reference = ProposalRef(ref)

	default:
		return nil, fmt.Errorf("mls/messages: unknown ProposalOrRef type %d", rawType)
	}

	return out, nil
}

// Marshal encodes a ProposalOrRef.
func (p *ProposalOrRef) Marshal(w *mlstls.Writer) error {
	w.Uint8(uint8(p.Type))

	switch p.Type {
	case ProposalOrRefTypeProposal:
		if p.Proposal == nil {
			return fmt.Errorf("mls/messages: a by-value ProposalOrRef with no proposal")
		}
		return p.Proposal.Marshal(w)

	case ProposalOrRefTypeReference:
		if len(p.Reference) == 0 {
			return fmt.Errorf("mls/messages: a by-reference ProposalOrRef with an empty reference")
		}
		w.Opaque(p.Reference)
		return nil

	default:
		return fmt.Errorf("mls/messages: unknown ProposalOrRef type %d", p.Type)
	}
}

// Hash returns a hash of the encoded proposal.
//
// It is NOT the reference a commit cites: that one is
// RefHash("MLS 1.0 Proposal Reference", proposal), computed by MakeProposalReference in
// proposal_cache.go. This method is kept only for callers that want an unlabelled digest for
// their own bookkeeping, and anything that needs to interoperate must use the labelled form.
// The two were once conflated here, which is why the distinction is spelled out rather than
// left to the reader to infer from the names.
func (p *Proposal) Hash(suite crypto.CipherSuite) ([]byte, error) {
	encoded, err := MarshalProposal(p)
	if err != nil {
		return nil, err
	}
	return suite.Hash(encoded), nil
}

// parseLeafNodeFrom is a thin adapter so this package does not need the tree package's
// unexported helpers.
func parseLeafNodeFrom(r *mlstls.Reader) (*tree.LeafNode, error) {
	return tree.ParseLeafNode(r)
}
