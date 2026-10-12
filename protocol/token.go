package protocol

import (
	"encoding/binary"
	"fmt"
)

// Metadata protection — rotating delivery tokens (SCHAT.md section 4.7).
//
// Content encryption alone still leaves the relay server able to build a social
// graph: it sees that connection X sent 40 messages to connection Y. SCS-1
// removes that by giving every user a set of anonymous, short-lived mailbox
// addresses.
//
//	token_i = HKDF(ikm = routeKey, salt = LabelMailbox,
//	               info = LE64(epoch) || LE32(i), len = 16)
//	epoch   = floor(unix_time / 86400)
//
// The user hands a batch of these tokens to each contact over an already
// established end-to-end encrypted session. Sending a message means choosing an
// unused token; the envelope carries no sender identifier at all. The server
// therefore knows only "some connection is depositing into mailbox T", and T
// rotates every 24 hours.
//
// What this does NOT hide: an adversary who can observe the whole network,
// such as an ISP or a nation state, can still correlate timing, IP addresses and
// packet sizes. SCHAT.md section 4.7 states that limit explicitly rather than
// implying protection it does not provide.

// TokenSize is the length of a delivery token in bytes.
const TokenSize = 16

// TokenLifetimeSeconds is the rotation period of a delivery token.
const TokenLifetimeSeconds = 86400

// TokenBatchSize is how many tokens a user hands to each contact. A ring of
// tokens is used rather than a single value so that two messages in the same day
// are not linkable to each other.
const TokenBatchSize = 32

// DeliveryToken derives the token for a given epoch and ring index.
//
// Both inputs are public values, so this is a deterministic function; the
// secrecy comes entirely from routeKey, which never leaves the device.
func DeliveryToken(routeKey []byte, epoch uint64, index uint32) ([TokenSize]byte, error) {
	var token [TokenSize]byte
	if len(routeKey) != KeySize {
		return token, fmt.Errorf("%w: route key must be %d bytes, got %d",
			ErrBadKeySize, KeySize, len(routeKey))
	}

	ctx := make([]byte, 0, 12)
	ctx = binary.LittleEndian.AppendUint64(ctx, epoch)
	ctx = binary.LittleEndian.AppendUint32(ctx, index)

	raw, err := DeriveLabeled(routeKey, LabelMailbox, ctx, TokenSize)
	if err != nil {
		return token, err
	}
	defer Zero(raw)

	copy(token[:], raw)
	return token, nil
}

// EpochFor converts a Unix timestamp into a token epoch.
//
// Tokens are rotated on a fixed 24-hour boundary rather than a rolling window,
// so that a client that has been offline can still compute which epoch it needs
// without knowing when the peer last came online.
func EpochFor(unixSeconds int64) uint64 {
	if unixSeconds < 0 {
		return 0
	}
	return uint64(unixSeconds) / TokenLifetimeSeconds
}
