package protocol

// Protocol version identifiers.
//
// WireVersion is the single byte that appears at the start of every SCS-1
// frame header. It is bound into the session's additional authenticated data
// so that an attacker cannot force a downgrade to an older, weaker revision.
const (
	// Version is the SCS-1 protocol revision implemented by this package.
	Version = 1

	// WireVersion is the on-the-wire encoding of Version.
	WireVersion byte = 0x01

	// VersionString is a human readable identifier for logs and UI.
	VersionString = "SCS-1/v1"
)

// Implementation version of the protocol library itself (not the wire format).
const (
	// LibraryVersion is the semantic version of this Go module.
	LibraryVersion = "0.1.0-alpha"

	// GroupProtocolMLS records that group messaging uses IETF MLS (RFC 9420)
	// rather than a bespoke sender-key scheme. See SCHAT.md section 4.6.
	GroupProtocolMLS = "MLS/RFC9420"
)
