// Package signaling carries WebRTC session description and ICE candidate
// exchange, so that two clients can open a direct peer-to-peer path and move
// large files without the relay ever touching the bytes.
//
// STATUS: step 7 of the roadmap.
//
// Keeping bulk media off the relay serves three requirements at once: the server
// stays tiny (SCHAT.md section 8.1), user data never reaches it at all
// (section 7), and a multi-gigabyte video transfer is limited by the peers'
// bandwidth rather than by the operator's.
//
// The types below are the wire shapes the client can be written against now.
// They contain no key material and no plaintext: signalling describes how to
// reach a peer, not what will be said once connected.
package signaling

import "errors"

// ErrNotImplemented is returned by every stub in this package.
var ErrNotImplemented = errors.New("signaling: not implemented yet (roadmap step 7)")

// Kind distinguishes the two signalling message shapes.
type Kind string

const (
	// KindOffer carries an SDP offer from the initiating peer.
	KindOffer Kind = "offer"

	// KindAnswer carries an SDP answer from the responding peer.
	KindAnswer Kind = "answer"

	// KindCandidate carries one trickled ICE candidate.
	KindCandidate Kind = "candidate"

	// KindBye tells the peer that the direct path is closing.
	KindBye Kind = "bye"
)

// Message is one signalling payload, relayed verbatim between two peers.
type Message struct {
	// Kind selects which field below is meaningful.
	Kind Kind `json:"kind"`

	// SDP is the session description for offer and answer.
	SDP string `json:"sdp,omitempty"`

	// Candidate is the ICE candidate line for KindCandidate.
	Candidate string `json:"candidate,omitempty"`

	// SDPMid and SDPMLineIndex place a candidate within the session description.
	SDPMid        string `json:"sdp_mid,omitempty"`
	SDPMLineIndex uint16 `json:"sdp_mline_index,omitempty"`

	// TransferID groups the messages belonging to one file transfer. It is
	// chosen at random by the sender and reveals nothing about the content.
	TransferID string `json:"transfer_id,omitempty"`
}

// Relay forwards a signalling message to the peer's live connections.
//
// STATUS: stub — returns ErrNotImplemented.
func Relay(peerToken [16]byte, msg Message) error {
	return ErrNotImplemented
}
