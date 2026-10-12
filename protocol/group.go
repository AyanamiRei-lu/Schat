package protocol

import (
	"encoding/binary"
	"fmt"
)

// Group messaging: bridging MLS to the SCS-1 content layer
// (SCHAT.md section 4.6.2).
//
// SCHAT uses IETF MLS (RFC 9420) for group key agreement — TreeKEM, epochs,
// proposals, commits and welcomes — which is what gives group chat the same
// forward secrecy and post-compromise security as a 1:1 session. MLS is
// implemented in the mls subpackage (step 6a of the roadmap).
//
// MLS deliberately stops at "here is a shared secret for this epoch". It does
// not dictate how content is encrypted. SCS-1 supplies that half, and the two
// are joined through the MLS exporter:
//
//	epochKey = MLS_Export(exporterSecret, label = LabelGroup,
//	                      context = groupID, len = 32)
//	SK_i     = HKDF(epochKey, info = LabelGroup || LE32(senderLeafIndex), len = 32)
//
// This is the design's main originality claim for groups, and it buys three
// concrete things:
//
//   - group messages and 1:1 messages share one content encryption path, so
//     there is no second implementation to get wrong;
//   - the per-file-format AEAD matrix (section 5 of the spec) applies unchanged
//     inside groups, so media needs no group-specific crypto;
//   - MLS handles the genuinely hard part — membership changes with
//     post-compromise security — while SCS-1 handles formatting, padding and
//     integrity uniformly.

// GroupEpochKey derives the SCS content key from an MLS exporter secret.
//
// caller-supplied groupID is bound in as the exporter context, so two groups
// that somehow reached the same epoch secret would still produce unrelated
// content keys.
func GroupEpochKey(exporterSecret, groupID []byte) ([]byte, error) {
	if len(exporterSecret) == 0 {
		return nil, fmt.Errorf("%w: empty MLS exporter secret", ErrBadKeySize)
	}
	return DeriveLabeled(exporterSecret, LabelGroup, groupID, KeySize)
}

// SenderChainKey derives a member's sending chain key from the epoch key.
//
// Each member has an independent chain, so sending is O(1) regardless of group
// size, and the leaf index prevents two members from ever sharing a chain.
func SenderChainKey(epochKey []byte, senderLeafIndex uint32) ([]byte, error) {
	if len(epochKey) != KeySize {
		return nil, fmt.Errorf("%w: epoch key must be %d bytes, got %d",
			ErrBadKeySize, KeySize, len(epochKey))
	}
	var ctx [4]byte
	binary.LittleEndian.PutUint32(ctx[:], senderLeafIndex)
	return DeriveLabeled(epochKey, LabelGroup, ctx[:], KeySize)
}
