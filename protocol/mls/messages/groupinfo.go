package messages

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
	"github.com/schat/schat/protocol/mls/tree"
)

// GroupInfo (RFC 9420 section 12.4.3).
//
//	struct {
//	    GroupContext group_context;
//	    Extension extensions<V>;
//	    MAC confirmation_tag;
//	    uint32 signer;
//	    /* SignWithLabel(., "GroupInfoTBS", GroupInfoTBS) */
//	    opaque signature<V>;
//	} GroupInfo;
//
// A GroupInfo is what a Welcome hands to a new member so that it can construct the epoch: the
// group's public state, the confirmation tag proving the sender computed that epoch, and the
// leaf index of whoever signed it.
//
// # The group context is carried as bytes
//
// The group_context field is a GroupContext structure, not an opaque blob — but this package
// does not need to interpret it, only to carry it and to put it into the signed bytes. Keeping
// the encoded form has two advantages: it makes it impossible for two packages to disagree
// about an encoding, and it keeps the schedule package's verified encoder as the only thing
// that produces one.
//
// The fields are read in the order the encoding defines — version, cipher suite, group id,
// EPOCH, tree hash, confirmed transcript hash, extensions — which was confirmed byte for byte
// against the official key-schedule vectors before this file was written. The epoch's position
// between the group id and the hashes is the part most easily misread.

// GroupInfo is the group state a new member receives.
type GroupInfo struct {
	// GroupContext is the ENCODED group context, exactly as it appears on the wire.
	GroupContext []byte

	Extensions []tree.Extension

	// ConfirmationTag proves the sender computed the epoch the context describes. It is the
	// same tag a commit would carry for that epoch.
	ConfirmationTag []byte

	// Signer is the LEAF index of the member that signed this GroupInfo — not a node index,
	// and not the leaf's position in some other numbering.
	Signer uint32

	Signature []byte
}

// GroupInfoTBSBytes builds the bytes the signature covers: every field except the signature.
//
// The specification writes GroupInfoTBS as the same structure without the signature field,
// which is the pattern KeyPackage also follows. That reading comes from the comment beside the
// definition; if section 12.4.3.1 gives the structure explicitly, it should be checked against
// it before this is relied on for interoperability.
func (g *GroupInfo) GroupInfoTBSBytes() ([]byte, error) {
	if len(g.GroupContext) == 0 {
		return nil, fmt.Errorf("mls/messages: a GroupInfo needs a group context")
	}
	if len(g.ConfirmationTag) == 0 {
		return nil, fmt.Errorf("mls/messages: a GroupInfo needs a confirmation tag; without it a " +
			"new member cannot tell that the sender computed the same epoch")
	}

	w := mlstls.NewWriter(256)
	w.Raw(g.GroupContext)
	writeExtensionsOf(w, g.Extensions)
	w.Opaque(g.ConfirmationTag)
	w.Uint32(g.Signer)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// SignGroupInfo signs the GroupInfo with the signer's signature key.
func SignGroupInfo(g *GroupInfo, signatureKey []byte) ([]byte, error) {
	tbs, err := g.GroupInfoTBSBytes()
	if err != nil {
		return nil, err
	}
	return crypto.SignWithLabel(signatureKey, "GroupInfoTBS", tbs)
}

// VerifyGroupInfo checks the signature and the fields a new member must not accept blindly.
//
// expectedGroupContext is the context the member believes it is joining: a GroupInfo describing
// a different group must be refused rather than used, or the member would construct an epoch
// for a group nobody else is in.
func VerifyGroupInfo(g *GroupInfo, expectedGroupContext []byte, signerSignatureKey []byte) error {
	if g == nil {
		return fmt.Errorf("mls/messages: no GroupInfo")
	}
	if len(expectedGroupContext) != 0 && string(g.GroupContext) != string(expectedGroupContext) {
		return fmt.Errorf("mls/messages: the GroupInfo describes a different group context than " +
			"the one this member is joining")
	}
	if len(g.Signature) == 0 {
		return fmt.Errorf("mls/messages: the GroupInfo is unsigned")
	}

	tbs, err := g.GroupInfoTBSBytes()
	if err != nil {
		return err
	}
	if err := crypto.VerifyWithLabel(signerSignatureKey, "GroupInfoTBS", tbs, g.Signature); err != nil {
		return fmt.Errorf("mls/messages: the GroupInfo signature does not verify: %w", err)
	}
	return nil
}

// ParseGroupInfo decodes a GroupInfo.
func ParseGroupInfo(r *mlstls.Reader) (*GroupInfo, error) {
	out := &GroupInfo{}

	context, err := readGroupContextBytes(r)
	if err != nil {
		return nil, err
	}
	out.GroupContext = context

	if out.Extensions, err = parseExtensionsOf(r); err != nil {
		return nil, err
	}
	if out.ConfirmationTag, err = r.Opaque(); err != nil {
		return nil, err
	}
	if out.Signer, err = r.Uint32(); err != nil {
		return nil, err
	}
	if out.Signature, err = r.Opaque(); err != nil {
		return nil, err
	}
	return out, nil
}

// Marshal writes a GroupInfo.
func (g *GroupInfo) Marshal(w *mlstls.Writer) error {
	w.Raw(g.GroupContext)
	writeExtensionsOf(w, g.Extensions)
	w.Opaque(g.ConfirmationTag)
	w.Uint32(g.Signer)
	w.Opaque(g.Signature)
	return nil
}

// MarshalGroupInfo encodes a GroupInfo and returns the bytes.
func MarshalGroupInfo(g *GroupInfo) ([]byte, error) {
	w := mlstls.NewWriter(512)
	if err := g.Marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// readGroupContextBytes reads a GroupContext and returns its encoding unchanged.
//
// It re-encodes what it read rather than slicing the input, so that a context with a
// non-minimal length prefix is rejected by the writer instead of being passed along — the same
// rule the reader already applies to every other vector.
func readGroupContextBytes(r *mlstls.Reader) ([]byte, error) {
	version, err := r.Uint16()
	if err != nil {
		return nil, err
	}
	cipherSuite, err := r.Uint16()
	if err != nil {
		return nil, err
	}
	groupID, err := r.Opaque()
	if err != nil {
		return nil, err
	}
	epoch, err := r.Uint64()
	if err != nil {
		return nil, err
	}
	treeHash, err := r.Opaque()
	if err != nil {
		return nil, err
	}
	confirmedTranscriptHash, err := r.Opaque()
	if err != nil {
		return nil, err
	}
	extensions, err := r.Opaque()
	if err != nil {
		return nil, err
	}

	w := mlstls.NewWriter(128)
	w.Uint16(version)
	w.Uint16(cipherSuite)
	w.Opaque(groupID)
	w.Uint64(epoch)
	w.Opaque(treeHash)
	w.Opaque(confirmedTranscriptHash)
	w.Opaque(extensions)
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
