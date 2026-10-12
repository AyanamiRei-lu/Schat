package messages

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// Transcript hashes (RFC 9420 section 8.2).
//
//	confirmed_transcript_hash_[0] = ""   /* zero-length octet string */
//	interim_transcript_hash_[0]   = ""
//
//	confirmed_transcript_hash_[epoch] =
//	    Hash(interim_transcript_hash_[epoch - 1] || ConfirmedTranscriptHashInput_[epoch])
//
//	interim_transcript_hash_[epoch] =
//	    Hash(confirmed_transcript_hash_[epoch] || InterimTranscriptHashInput_[epoch])
//
// # What the two chains are for, and why the order matters
//
// The confirmed hash covers every commit up to and including the one that opened this epoch.
// The interim hash then covers the confirmation tag ON TOP of that — which is what makes the
// chain continue: the next epoch's confirmed hash starts from the previous epoch's interim
// hash, so each confirmation tag is folded into the transcript that the following commit
// signs.
//
// Two consequences that are easy to get backwards:
//
//   - The commit that opens epoch N is sent IN epoch N-1, so the content's epoch field is
//     N-1 while the hashes being computed are epoch N's. A commit's own epoch number is
//     therefore not the epoch it creates, and code that assumed otherwise would compute
//     every hash one step out.
//
//   - The confirmation tag is computed over the CONFIRMED hash of its own epoch, and the
//     interim hash is computed afterwards. Using the interim hash where the confirmed one
//     belongs produces a chain that verifies against itself and against nobody else.
//
// # The input shapes
//
// The specification gives the two inputs as structures; the byte layout below follows the
// data-flow figure in section 8.2, which labels them as wire_format, content and signature
// for the confirmed input, and the confirmation tag for the interim one.
//
//	ConfirmedTranscriptHashInput = wire_format ‖ content ‖ signature
//	InterimTranscriptHashInput   = confirmation_tag
//
// Note that these are NOT wrapped in the "MLS 1.0" labelled-hash construction used elsewhere:
// the transcript hash is Hash(previous || input), with no label.

// ConfirmedTranscriptHashInput encodes the input to the confirmed transcript hash.
//
// The content must be the commit that opened the epoch, with its OWN epoch field — that is,
// the epoch it was sent in, one less than the epoch being created.
func ConfirmedTranscriptHashInput(
	wireFormat WireFormat,
	content *FramedContent,
	signature []byte,
) ([]byte, error) {
	if content == nil {
		return nil, fmt.Errorf("mls/messages: no content for the transcript hash")
	}
	if content.Type != ContentTypeCommit {
		return nil, fmt.Errorf("mls/messages: the transcript is advanced by a commit, and this "+
			"content is type %d", content.Type)
	}

	w := mlstls.NewWriter(256)
	w.Uint16(uint16(wireFormat))
	if err := content.Marshal(w); err != nil {
		return nil, err
	}
	w.Opaque(signature)

	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// InterimTranscriptHashInput encodes the input to the interim transcript hash.
func InterimTranscriptHashInput(confirmationTag []byte) ([]byte, error) {
	if len(confirmationTag) == 0 {
		return nil, fmt.Errorf("mls/messages: no confirmation tag for the interim transcript hash")
	}

	w := mlstls.NewWriter(len(confirmationTag) + 4)
	w.Opaque(confirmationTag)
	if err := w.Err(); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// Transcript is one member's view of the two hash chains.
type Transcript struct {
	Confirmed []byte
	Interim   []byte
}

// NewTranscript returns the transcript of a brand-new group: both hashes are the zero-length
// octet string, not a hash of anything.
func NewTranscript() Transcript {
	return Transcript{Confirmed: []byte{}, Interim: []byte{}}
}

// Advance moves the transcript to the next epoch using the commit that opened it.
//
// It returns the new transcript, and leaves the receiver untouched so that a caller which
// rejects the commit afterwards still holds the epoch it was validating against.
func (t Transcript) Advance(
	wireFormat WireFormat,
	commitContent *FramedContent,
	signature []byte,
	confirmationTag []byte,
	suite crypto.CipherSuite,
) (Transcript, error) {
	confirmedInput, err := ConfirmedTranscriptHashInput(wireFormat, commitContent, signature)
	if err != nil {
		return t, err
	}
	interimInput, err := InterimTranscriptHashInput(confirmationTag)
	if err != nil {
		return t, err
	}

	confirmed := suite.Hash(concat(t.Interim, confirmedInput))
	interim := suite.Hash(concat(confirmed, interimInput))

	return Transcript{Confirmed: confirmed, Interim: interim}, nil
}

// ConfirmationTag computes the tag a commit must carry for this epoch.
//
// The tag is a MAC under the epoch's confirmation key over the CONFIRMED transcript hash of
// the epoch the commit opens — which is why this function takes the hash that Advance
// produces, and why computing the tag from the interim hash instead would produce a value
// that verifies against itself and nothing else.
func ConfirmationTag(confirmationKey, confirmedTranscriptHash []byte, suite crypto.CipherSuite) ([]byte, error) {
	if len(confirmationKey) == 0 {
		return nil, fmt.Errorf("mls/messages: no confirmation key")
	}
	return crypto.MAC(confirmationKey, confirmedTranscriptHash, suite)
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}
