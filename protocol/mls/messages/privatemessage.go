package messages

import (
	"fmt"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// Private messages: the structure and the two associated-data constructions
// (RFC 9420 section 6.3).
//
//	struct {
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    ContentType content_type;
//	    opaque authenticated_data<V>;
//	    opaque encrypted_sender_data<V>;
//	    opaque ciphertext<V>;
//	} PrivateMessage;
//
//	struct { opaque group_id<V>; uint64 epoch; ContentType content_type;
//	         opaque authenticated_data<V>; } PrivateContentAAD;
//
//	struct { uint32 leaf_index; uint32 generation; opaque reuse_guard[4]; } SenderData;
//
//	struct { opaque group_id<V>; uint64 epoch; ContentType content_type; } SenderDataAAD;
//
// # Three details that look alike and are not
//
//  1. The two AADs differ. The content's includes authenticated_data; the sender data's does
//     NOT — it is only the first three fields. Using one construction for both produces
//     messages that this implementation reads correctly and no other implementation does.
//
//  2. reuse_guard is a FIXED four-byte field, not a variable-length vector. It exists to
//     randomise the nonce: the sender draws a fresh guard per message and encrypts under
//     nonce XOR (reuse_guard padded with zeros). Encoding it as a vector, or omitting the XOR,
//     yields a message only its author can open.
//
//  3. leaf_index and generation in SenderData are what a receiver uses to find the right
//     ratchet and generation in the secret tree. Reading the receiver's own ratchet position
//     instead of the generation the message names makes every out-of-order message
//     undecryptable.
//
// # What this file does not do
//
// It encodes and decodes; it performs no cryptography. Sealing and opening belong with the
// caller that holds the epoch's secret tree, and keeping them out of here means this file can
// be checked by round-tripping rather than argued about.

// ReuseGuardSize is fixed by the specification: `opaque reuse_guard[4]`.
const ReuseGuardSize = 4

// SenderData is the part of a private message that identifies its sender, encrypted under a
// key derived from the epoch's sender-data secret and a sample of the ciphertext.
type SenderData struct {
	LeafIndex  uint32
	Generation uint32
	ReuseGuard [ReuseGuardSize]byte
}

// PrivateMessage is an encrypted application or handshake message.
type PrivateMessage struct {
	GroupID             []byte
	Epoch               uint64
	ContentType         ContentType
	AuthenticatedData   []byte
	EncryptedSenderData []byte
	Ciphertext          []byte
}

// PrivateContentAAD builds the associated data for a private message's content.
//
// It includes authenticated_data, which the SenderDataAAD below deliberately does not: the two
// protect different things and the specification gives them different inputs.
func PrivateContentAAD(groupID []byte, epoch uint64, contentType ContentType, authenticatedData []byte) ([]byte, error) {
	w := mlstls.NewWriter(len(groupID) + len(authenticatedData) + 16)
	w.Opaque(groupID)
	w.Uint64(epoch)
	w.Uint8(uint8(contentType))
	w.Opaque(authenticatedData)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// SenderDataAAD builds the associated data for a private message's sender data.
func SenderDataAAD(groupID []byte, epoch uint64, contentType ContentType) ([]byte, error) {
	w := mlstls.NewWriter(len(groupID) + 12)
	w.Opaque(groupID)
	w.Uint64(epoch)
	w.Uint8(uint8(contentType))

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// MarshalSenderData encodes the sender data that goes inside encrypted_sender_data.
func MarshalSenderData(sd *SenderData) ([]byte, error) {
	if sd == nil {
		return nil, fmt.Errorf("mls/messages: no sender data")
	}

	w := mlstls.NewWriter(12)
	w.Uint32(sd.LeafIndex)
	w.Uint32(sd.Generation)
	// A fixed field, written as four bytes and not as a vector: a length prefix here would
	// shift everything after it.
	w.Raw(sd.ReuseGuard[:])

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// ParseSenderData decodes the sender data.
func ParseSenderData(r *mlstls.Reader) (*SenderData, error) {
	out := &SenderData{}

	var err error
	if out.LeafIndex, err = r.Uint32(); err != nil {
		return nil, err
	}
	if out.Generation, err = r.Uint32(); err != nil {
		return nil, err
	}

	guard, err := r.Raw(ReuseGuardSize)
	if err != nil {
		return nil, err
	}
	copy(out.ReuseGuard[:], guard)

	return out, nil
}

// ParsePrivateMessage decodes a private message.
func ParsePrivateMessage(r *mlstls.Reader) (*PrivateMessage, error) {
	out := &PrivateMessage{}

	var err error
	if out.GroupID, err = r.Opaque(); err != nil {
		return nil, err
	}
	if out.Epoch, err = r.Uint64(); err != nil {
		return nil, err
	}

	rawType, err := r.Uint8()
	if err != nil {
		return nil, err
	}
	out.ContentType = ContentType(rawType)

	if out.AuthenticatedData, err = r.Opaque(); err != nil {
		return nil, err
	}
	if out.EncryptedSenderData, err = r.Opaque(); err != nil {
		return nil, err
	}
	if out.Ciphertext, err = r.Opaque(); err != nil {
		return nil, err
	}
	return out, nil
}

// Marshal encodes a private message.
func (p *PrivateMessage) Marshal(w *mlstls.Writer) error {
	w.Opaque(p.GroupID)
	w.Uint64(p.Epoch)
	w.Uint8(uint8(p.ContentType))
	w.Opaque(p.AuthenticatedData)
	w.Opaque(p.EncryptedSenderData)
	w.Opaque(p.Ciphertext)
	return nil
}

// MarshalPrivateMessage encodes a private message and returns the bytes.
func MarshalPrivateMessage(p *PrivateMessage) ([]byte, error) {
	w := mlstls.NewWriter(256)
	if err := p.Marshal(w); err != nil {
		return nil, err
	}
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
