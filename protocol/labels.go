package protocol

// Domain separation labels (SCHAT.md section 4.3).
//
// Every key derivation in SCS-1 is bound to exactly one label. This is what
// stops a key derived for one purpose from being valid for another: an attacker
// who can make the victim derive a "chunk key" where a "message key" was
// expected gains nothing, because the label makes the two outputs unrelated.
//
// The labels are part of the frozen wire contract. Changing any of them breaks
// compatibility with every existing session and MUST be accompanied by a
// WireVersion bump.
const (
	// LabelRoot labels root key derivation during session establishment.
	LabelRoot = "SCS1/root/v1"

	// LabelChain labels symmetric ratchet chain advances.
	LabelChain = "SCS1/chain/v1"

	// LabelMsg labels per-message key derivation.
	LabelMsg = "SCS1/msg/v1"

	// LabelFile labels the per-file root key.
	LabelFile = "SCS1/file/v1"

	// LabelChunk labels the chunk key ladder.
	LabelChunk = "SCS1/chunk/v1"

	// LabelWrap labels key wrapping (delivering file or group keys).
	LabelWrap = "SCS1/wrap/v1"

	// LabelVault labels the local encrypted database key.
	LabelVault = "SCS1/vault/v1"

	// LabelMailbox labels delivery token derivation.
	LabelMailbox = "SCS1/mbx/v1"

	// LabelGroup labels the exporter that unifies MLS epochs with the SCS-1
	// content layer (SCHAT.md section 4.6.2).
	LabelGroup = "SCS1/group/v1"

	// LabelCall labels real-time audio/video frame encryption.
	LabelCall = "SCS1/call/v1"

	// LabelSafety labels safety number (identity verification) derivation.
	LabelSafety = "SCS1/safety/v1"

	// LabelTranscript labels the handshake transcript hash that is folded into
	// the root key salt to bind both identities and the protocol version.
	LabelTranscript = "SCS1/transcript/v1"
)

// AllLabels returns every domain separation label defined by SCS-1.
//
// It exists so that the test suite can assert uniqueness: two features sharing
// a label would silently reintroduce the cross-protocol key reuse that labels
// exist to prevent.
func AllLabels() []string {
	return []string{
		LabelRoot,
		LabelChain,
		LabelMsg,
		LabelFile,
		LabelChunk,
		LabelWrap,
		LabelVault,
		LabelMailbox,
		LabelGroup,
		LabelCall,
		LabelSafety,
		LabelTranscript,
	}
}

// Direction bytes for the message key derivation (SCHAT.md section 4.5).
//
// Folding the direction into the message key means the same chain counter
// produces different keys in each direction. This defeats reflection attacks,
// where an attacker bounces a victim's own ciphertext back at them.
const (
	// DirAToB is the direction byte used by the session initiator.
	DirAToB byte = 0x41 // 'A'

	// DirBToA is the direction byte used by the session responder.
	DirBToA byte = 0x42 // 'B'
)

// chainAdvanceTag is the HMAC input when advancing a symmetric ratchet chain,
// as specified in SCHAT.md section 4.5.
const chainAdvanceTag byte = 0x02
