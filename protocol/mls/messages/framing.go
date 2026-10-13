// Message framing (RFC 9420 sections 6 and 12.1).
//
// # The one detail that decides whether anything parses
//
// WireFormat is a uint16 in the specification, spelled out explicitly as `uint16 WireFormat`
// with a comment pointing at the IANA registry. ContentType and SenderType are one-byte
// enums. They look like a set and are not: two bytes versus one, in the first field of every
// message a client ever reads. Writing all three the same way — which is what reading the
// names rather than the text produces — makes every message unparseable, and the failure
// arrives as a length or bounds error far from the cause.
//
// The rest of the structures here were taken from the text the same way.
//
// # What is complete
//
// All three content types: application data, a proposal, and a commit. A commit is
// implementable now because its two fields already exist — ProposalOrRef from this package
// and UpdatePath from the tree package — so there is no reason to leave it out and no
// guessing involved.
package messages

import (
	"fmt"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// WireFormat is a TWO-BYTE value. See the package comment: this is the field most likely to
// be written as one byte by mistake.
type WireFormat uint16

// Values from the IANA MLS Wire Formats registry.
const (
	WireFormatPublicMessage  WireFormat = 1
	WireFormatPrivateMessage WireFormat = 2
	WireFormatWelcome        WireFormat = 3
	WireFormatGroupInfo      WireFormat = 4
	WireFormatKeyPackage     WireFormat = 5
)

// ContentType is a one-byte enum.
type ContentType uint8

const (
	ContentTypeReserved    ContentType = 0
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

// SenderType is a one-byte enum.
type SenderType uint8

const (
	SenderTypeReserved          SenderType = 0
	SenderTypeMember            SenderType = 1
	SenderTypeExternal          SenderType = 2
	SenderTypeNewMemberProposal SenderType = 3
	SenderTypeNewMemberCommit   SenderType = 4
)

// Sender identifies who sent a framed message.
//
// Only a member's sender carries a position, and it is a LEAF index — the same distinction as
// in a Remove proposal, and the same confusion if it is read as a node index.
type Sender struct {
	Type SenderType

	// LeafIndex is set when Type is member.
	LeafIndex uint32

	// SenderIndex is set when Type is external: it indexes the group's external senders list,
	// not the tree.
	SenderIndex uint32
}

// FramedContent is the authenticated body of an MLS message.
type FramedContent struct {
	GroupID           []byte
	Epoch             uint64
	Sender            Sender
	AuthenticatedData []byte

	Type ContentType

	ApplicationData []byte
	Proposal        *Proposal
	Commit          *Commit
}

// Commit is a batch of proposals applied together, plus the sender's update path.
//
// The proposals are references as often as they are values: a member that already sent a
// proposal refers to it by hash rather than repeating it, which is why a receiver has to keep
// the proposals it has seen (section 12.4's caching requirement) before it can process a
// commit at all.
type Commit struct {
	Proposals []*ProposalOrRef

	// Path is optional: a commit that only removes a member carries no update path.
	Path *tree.UpdatePath
}

// FramedContentAuthData carries the signature over a framed content and, for commits, the
// confirmation tag.
type FramedContentAuthData struct {
	Signature []byte

	// ConfirmationTag is present only for commits. It is a MAC under the epoch's confirmation
	// key over the confirmed transcript hash, which is what lets a member prove it computed
	// the same epoch as everyone else.
	ConfirmationTag []byte
}

// AuthenticatedContent is a framed content together with its authentication.
type AuthenticatedContent struct {
	WireFormat WireFormat
	Content    FramedContent
	Auth       FramedContentAuthData
}

// ParseFramedContent decodes a FramedContent.
func ParseFramedContent(r *mlstls.Reader) (*FramedContent, error) {
	out := &FramedContent{}

	var err error
	if out.GroupID, err = r.Opaque(); err != nil {
		return nil, err
	}
	if out.Epoch, err = r.Uint64(); err != nil {
		return nil, err
	}

	sender, err := parseSender(r)
	if err != nil {
		return nil, err
	}
	out.Sender = sender

	if out.AuthenticatedData, err = r.Opaque(); err != nil {
		return nil, err
	}

	rawType, err := r.Uint8()
	if err != nil {
		return nil, err
	}
	out.Type = ContentType(rawType)

	switch out.Type {
	case ContentTypeApplication:
		if out.ApplicationData, err = r.Opaque(); err != nil {
			return nil, err
		}

	case ContentTypeProposal:
		proposal, err := ParseProposal(r)
		if err != nil {
			return nil, err
		}
		out.Proposal = proposal

	case ContentTypeCommit:
		commit, err := parseCommit(r)
		if err != nil {
			return nil, err
		}
		out.Commit = commit

	default:
		return nil, fmt.Errorf("mls/messages: unknown content type %d", rawType)
	}

	return out, nil
}

// Marshal encodes a FramedContent.
func (f *FramedContent) Marshal(w *mlstls.Writer) error {
	w.Opaque(f.GroupID)
	w.Uint64(f.Epoch)
	f.Sender.marshal(w)
	w.Opaque(f.AuthenticatedData)
	w.Uint8(uint8(f.Type))

	switch f.Type {
	case ContentTypeApplication:
		w.Opaque(f.ApplicationData)
		return nil

	case ContentTypeProposal:
		if f.Proposal == nil {
			return fmt.Errorf("mls/messages: a proposal content with no proposal")
		}
		return f.Proposal.Marshal(w)

	case ContentTypeCommit:
		if f.Commit == nil {
			return fmt.Errorf("mls/messages: a commit content with no commit")
		}
		return f.Commit.marshal(w)

	default:
		return fmt.Errorf("mls/messages: unknown content type %d", f.Type)
	}
}

func parseSender(r *mlstls.Reader) (Sender, error) {
	rawType, err := r.Uint8()
	if err != nil {
		return Sender{}, err
	}

	out := Sender{Type: SenderType(rawType)}

	switch out.Type {
	case SenderTypeMember:
		if out.LeafIndex, err = r.Uint32(); err != nil {
			return Sender{}, err
		}
	case SenderTypeExternal:
		if out.SenderIndex, err = r.Uint32(); err != nil {
			return Sender{}, err
		}
	case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
		// An empty struct on the wire: nothing to read.
	default:
		return Sender{}, fmt.Errorf("mls/messages: unknown sender type %d", rawType)
	}

	return out, nil
}

func (s *Sender) marshal(w *mlstls.Writer) {
	w.Uint8(uint8(s.Type))
	switch s.Type {
	case SenderTypeMember:
		w.Uint32(s.LeafIndex)
	case SenderTypeExternal:
		w.Uint32(s.SenderIndex)
	}
}

func parseCommit(r *mlstls.Reader) (*Commit, error) {
	out := &Commit{}

	err := r.Vector(func(r *mlstls.Reader) error {
		for !r.Empty() {
			ref, err := ParseProposalOrRef(r)
			if err != nil {
				return err
			}
			out.Proposals = append(out.Proposals, ref)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	present, err := r.Optional(func(r *mlstls.Reader) error {
		path, err := tree.ParseUpdatePath(r)
		if err != nil {
			return err
		}
		out.Path = path
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !present {
		out.Path = nil
	}

	return out, nil
}

func (c *Commit) marshal(w *mlstls.Writer) error {
	w.Vector(func(w *mlstls.Writer) error {
		for _, ref := range c.Proposals {
			if err := ref.Marshal(w); err != nil {
				return err
			}
		}
		return nil
	})

	if c.Path == nil {
		w.Optional(nil)
		return nil
	}
	path := c.Path
	w.Optional(func(w *mlstls.Writer) error { return path.MarshalTo(w) })
	return nil
}

// ParseFramedContentAuthData decodes the authentication for a content of the given type,
// which the encoding depends on: a commit carries a confirmation tag and the other types do
// not, so the type has to be known before the bytes can be read.
func ParseFramedContentAuthData(r *mlstls.Reader, contentType ContentType) (FramedContentAuthData, error) {
	var out FramedContentAuthData
	var err error

	if out.Signature, err = r.Opaque(); err != nil {
		return out, err
	}

	switch contentType {
	case ContentTypeCommit:
		if out.ConfirmationTag, err = r.Opaque(); err != nil {
			return out, err
		}
	case ContentTypeApplication, ContentTypeProposal:
		// An empty struct on the wire.
	default:
		return out, fmt.Errorf("mls/messages: unknown content type %d", contentType)
	}

	return out, nil
}

// Marshal encodes the authentication for a content of the given type.
func (a *FramedContentAuthData) Marshal(w *mlstls.Writer, contentType ContentType) error {
	w.Opaque(a.Signature)

	switch contentType {
	case ContentTypeCommit:
		w.Opaque(a.ConfirmationTag)
	case ContentTypeApplication, ContentTypeProposal:
	default:
		return fmt.Errorf("mls/messages: unknown content type %d", contentType)
	}
	return nil
}
