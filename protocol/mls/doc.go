// Package mls will implement the IETF Messaging Layer Security protocol
// (RFC 9420) for SCHAT group messaging.
//
// STATUS: step 6a is in progress. See docs/MLS-PLAN.md for the milestone breakdown and the
// per-milestone acceptance criteria.
//
//	M1  presentation language (this package's tls/ subpackage)   DONE
//	M2  ciphersuite and key schedule                             not started
//	M3  TreeKEM and tree hash                                    not started
//	M4  group creation, add/update/remove, commit processing      not started
//	M5  welcome and joining                                      not started
//	M6  relay integration and UI (step 6b)                       not started
//
// # Ciphersuite
//
//	MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519   (RFC 9420 suite 0x0003)
//
// Every primitive in this suite is already used by the SCS-1 pairwise layer:
// X25519, ChaCha20-Poly1305, SHA-256 and Ed25519. Choosing it means the project
// keeps a single identity key, a single AEAD implementation and a single set of
// constant-time and zeroization helpers. No new cryptographic dependency is
// introduced for groups.
//
// 0x0003 is the suite groups will USE. Suite 0x0001
// (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) must also be implemented, because that
// is where the bulk of the official test vectors live: byte-exact verification is the
// acceptance criterion for M2 to M5, and it can only be performed against vectors that
// exist. Supporting a second suite is cheap — both map onto crypto/hpke and the standard
// library's AES-GCM — and it turns "our suite happens to match" into "the implementation
// is checked against the vectors the working group published".

// # Scope
//
// This package owns group key agreement only:
//
//	ratchet tree, TreeKEM update paths        RFC 9420 section 7
//	KeyPackage and LeafNode                   RFC 9420 sections 7.2, 10.1
//	key schedule                              RFC 9420 section 8
//	secret tree and sender ratchets           RFC 9420 section 9
//	proposal and commit framework             RFC 9420 sections 12.1 to 12.4
//	welcome and group info                    RFC 9420 section 12.4.3
//	message framing                           RFC 9420 section 6
//	group state machine                       RFC 9420 sections 11 to 13
//
// # Content encryption does NOT go through the SCS-1 AEAD path
//
// An earlier version of this comment said that the MLS exporter secret would be fed to
// protocol.GroupEpochKey so that group content could reuse the same AEAD profile matrix as
// 1:1 messages. That was written before the implementation and it is wrong: RFC 9420's
// SecretTree exists to give every member a separate handshake and application ratchet, so
// that each message uses its own key and generation, replay is detected by generation, and
// one compromised sender secret does not expose the epoch's other messages or the past.
//
// Collapsing group content back onto a single exported epoch key would discard exactly
// those properties while still looking like "we use MLS". Group content therefore travels
// in MLS's own PrivateMessage framing, under a new relay content type (0x03) alongside the
// existing 0x01 SCS-1 frame and 0x02 handshake.
//
// The two layers stay separate: 1:1 messages use SCS-1, group messages use MLS, and
// neither borrows the other's framing.
//
// # Verification requirement
//
// Passing unit tests written by the same author as the implementation would not
// be credible for a protocol this intricate. This package MUST be validated
// byte-for-byte against the official IETF MLS test vectors before it is used for
// anything. That is an explicit completion criterion for step 6a (SCHAT.md
// section 13.3).
//
// # Delivery service caveat
//
// MLS assumes a Delivery Service that orders commits and relays messages. In
// SCHAT that role is played by the self-hosted server. By the nature of RFC 9420,
// the DS can observe which clients fetch messages for the same opaque group
// token, which means group membership is visible to the server even though
// message content is not. Closing that gap needs an anonymity-preserving DS and
// is listed as a v2 research item (SCHAT.md section 4.6.4).
package mls
