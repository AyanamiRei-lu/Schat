package messages

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// The signed part of a framed message (RFC 9420 section 6.1).
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    WireFormat wire_format;
//	    FramedContent content;
//	    select (FramedContentTBS.content.sender.sender_type) {
//	        case member:
//	        case new_member_commit:
//	            GroupContext context;
//	        case external:
//	        case new_member_proposal:
//	            struct{};
//	    };
//	} FramedContentTBS;
//
// # Three things in that structure carry the security
//
//   - `version = mls10` is a CONSTANT, written into the bytes rather than taken from anywhere.
//     It is what stops a signature made under one protocol version from being replayed under
//     another.
//
//   - The GroupContext is bound in for MEMBERS ONLY. That is what makes a member's signature
//     specific to one group and one epoch: the same content signed by the same key in a
//     different epoch produces a different TBS and therefore a different signature. It is
//     also why an external sender's signature cannot be replayed as a member's, or the
//     reverse: the two encode different bytes.
//
//   - The wire format is covered too, so a message signed to be sent as a PrivateMessage
//     cannot be presented as a PublicMessage.
//
// # GroupContext is passed as bytes
//
// This package encodes structures; it does not own group state. The caller supplies the
// already-encoded GroupContext for the epoch, which is what the key schedule uses and what
// the vectors verify — passing a re-encoded copy would risk the two disagreeing.

// ProtocolVersionMLS10 is the version constant written into every signed message.
const ProtocolVersionMLS10 uint16 = 1

// FramedContentTBS builds the bytes a sender signs or a receiver verifies.
//
// groupContext must be the encoded GroupContext of the epoch, and is used only when the
// sender is a member or a new member committing; for any other sender type it is ignored,
// which is the specification's rule rather than a convenience.
func FramedContentTBS(
	wireFormat WireFormat,
	content *FramedContent,
	groupContext []byte,
) ([]byte, error) {
	if content == nil {
		return nil, fmt.Errorf("mls/messages: no content to sign")
	}

	w := mlstls.NewWriter(256)
	w.Uint16(ProtocolVersionMLS10)
	w.Uint16(uint16(wireFormat))

	if err := content.Marshal(w); err != nil {
		return nil, err
	}

	switch content.Sender.Type {
	case SenderTypeMember, SenderTypeNewMemberCommit:
		if len(groupContext) == 0 {
			return nil, fmt.Errorf("mls/messages: a %d sender's content must be bound to a "+
				"group context, and none was supplied", content.Sender.Type)
		}
		w.Raw(groupContext)

	case SenderTypeExternal, SenderTypeNewMemberProposal:
		// An empty struct on the wire: the context is deliberately not bound.

	default:
		return nil, fmt.Errorf("mls/messages: unknown sender type %d", content.Sender.Type)
	}

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// SignFramedContent signs a content with the sender's signature key.
func SignFramedContent(
	wireFormat WireFormat,
	content *FramedContent,
	groupContext []byte,
	signatureKey []byte,
	suite crypto.CipherSuite,
) ([]byte, error) {
	tbs, err := FramedContentTBS(wireFormat, content, groupContext)
	if err != nil {
		return nil, err
	}
	if err := requireEd25519(suite); err != nil {
		return nil, err
	}
	return crypto.SignWithLabel(signatureKey, "FramedContentTBS", tbs)
}

// requireEd25519 refuses a cipher suite whose signature scheme is not Ed25519.
//
// The signing and verification helpers take no suite, because Ed25519 does not need one —
// which is exactly why this check has to exist somewhere. Suites 0x0002, 0x0005 and 0x0006
// sign with ECDSA; producing an Ed25519 signature under one of them would succeed locally and
// be rejected by every other implementation, with nothing in the failure pointing at the
// signature scheme.
func requireEd25519(suite crypto.CipherSuite) error {
	switch suite {
	case crypto.CipherSuite(0x0001), crypto.CipherSuite(0x0003):
		return nil
	default:
		return fmt.Errorf("mls/messages: cipher suite %#04x does not sign with Ed25519, and no "+
			"other signature scheme is implemented", uint16(suite))
	}
}

// VerifyFramedContentSignature checks a signature over a content.
//
// It returns an error for every failure — wrong key, altered content, different epoch,
// different wire format, different sender type — because a verifier that answered "false"
// for all of them would leave the caller to decide which one happened, and the caller cannot
// tell.
//
// signatureKey is the sender's SignaturePublicKey: the leaf's for a member, resolved from the
// sender's leaf index by the caller.
func VerifyFramedContentSignature(
	wireFormat WireFormat,
	content *FramedContent,
	groupContext []byte,
	signatureKey []byte,
	signature []byte,
	suite crypto.CipherSuite,
) error {
	if len(signature) == 0 {
		return fmt.Errorf("mls/messages: no signature to verify")
	}

	tbs, err := FramedContentTBS(wireFormat, content, groupContext)
	if err != nil {
		return err
	}

	if err := requireEd25519(suite); err != nil {
		return err
	}

	if err := crypto.VerifyWithLabel(signatureKey, "FramedContentTBS", tbs, signature); err != nil {
		return fmt.Errorf("mls/messages: the signature over this content does not verify: %w", err)
	}
	return nil
}

// VerifyAuthenticatedContent checks the signature on an AuthenticatedContent.
//
// It deliberately does NOT check the confirmation tag: that is a MAC under the epoch's
// confirmation key over the confirmed transcript hash, and it belongs with the group's epoch
// state rather than with message framing. Leaving it out here is not an omission to fix
// later — a caller that treated a verified signature as a verified commit would skip the only
// check that the sender computed the same epoch.
func VerifyAuthenticatedContent(
	ac *AuthenticatedContent,
	groupContext []byte,
	signatureKey []byte,
	suite crypto.CipherSuite,
) error {
	if ac == nil {
		return fmt.Errorf("mls/messages: no content to verify")
	}
	return VerifyFramedContentSignature(ac.WireFormat, &ac.Content, groupContext,
		signatureKey, ac.Auth.Signature, suite)
}
