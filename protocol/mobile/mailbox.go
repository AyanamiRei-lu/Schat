package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MailboxTokenSize is the length of a delivery token in bytes.
//
// It mirrors protocol.TokenSize, which is what the relay's router keys on.
const MailboxTokenSize = 16

// mailboxLabel domain-separates the MVP mailbox derivation from every other use of
// SHA-256 in this project.
const mailboxLabel = "schat-mvp-mailbox"

// MailboxToken derives the mailbox a peer's handshake initiation is delivered to,
// straight from their identity signing public key.
//
// # This is a documented compromise, and it is temporary
//
// SCHAT.md section 4.7 specifies rotating delivery tokens so that the relay cannot
// link a mailbox to an identity. That mechanism is implemented on the server, but the
// client does not use it yet, and it cannot: tokens are exchanged INSIDE an encrypted
// session, and the very first message of a relationship is the handshake that creates
// that session. Something has to be routable before any session exists.
//
// The interim answer is this function, and it gives up the property section 4.7 exists
// to provide:
//
//   - anyone holding an identity's public signing key can compute its mailbox and
//     subscribe to it, learning WHEN that identity receives traffic and that it is
//     using this relay at all;
//   - the relay itself sees the same thing.
//
// It does NOT weaken confidentiality. Message content is protected by SCS-1 and never
// depends on the mailbox being secret — a token is an address, not a key. An attacker
// who computes every mailbox in existence still cannot read a single byte.
//
// # Why the derivation lives here rather than in the client
//
// Both ends must compute the same value: the sender to address the envelope, the
// receiver to subscribe. Two independent implementations of "SHA-256 of a prefix and a
// key" is exactly the kind of duplication that drifts, and a drift here fails silently
// and completely — handshakes simply never arrive. Keeping it in the shared protocol
// binding means there is one definition, and the test suite can pin it.
//
// It is replaced when session-internal token exchange lands, at which point this
// function should be deleted rather than kept as a fallback: a fallback path here would
// preserve the metadata leak for any peer that failed to negotiate tokens.
func MailboxToken(identitySigningHex string) (string, error) {
	raw, err := hex.DecodeString(normaliseHex(identitySigningHex))
	if err != nil {
		return "", fmt.Errorf("scs1: identity is not valid hex: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("scs1: identity signing key must be 32 bytes, got %d", len(raw))
	}

	h := sha256.New()
	h.Write([]byte(mailboxLabel))
	h.Write(raw)

	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:MailboxTokenSize]), nil
}
