package mobile

import (
	"encoding/hex"
	"fmt"

	"github.com/schat/schat/protocol/mls/messages"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// Reading a group message's public header.
//
// # Why a client needs this before it can decrypt anything
//
// A group message is protected by ONE group's epoch secret, and a relay envelope carries only a
// delivery token — nothing that says which group the message belongs to. But the message itself
// says so in the clear:
//
//	PrivateMessage = { opaque group_id<V>; uint64 epoch; ContentType content_type; ... }
//
// The group id and the epoch are outside the ciphertext on purpose: a receiver has to know which
// key to reach for BEFORE it can decrypt anything, and no scheme can decrypt a message to find
// out how to decrypt it.
//
// # What this does NOT do
//
// It does not decrypt, and it does not authenticate anything. Both fields are covered by the
// AAD of the content ciphertext, so a message whose header was altered will FAIL to decrypt
// rather than open under the wrong group — but reading the header succeeds either way, and that
// distinction is deliberate: a client that could not read a tampered header could not tell
// "this is not for me" from "this was tampered with".

// GroupMessageHeaderResult is what a message says about itself in the clear.
type GroupMessageHeaderResult struct {
	// GroupIDHex is the group the message belongs to. It is NOT authenticated by this call;
	// decryption is what proves it.
	GroupIDHex string

	// Epoch is the epoch the sender was in. A receiver in a different epoch must not attempt to
	// decrypt: its keys are for another epoch, and the attempt would fail with an error that
	// says nothing useful.
	Epoch int64
}

// GroupMessageHeader reads the public header of a group message.
func GroupMessageHeader(messageHex string) (*GroupMessageHeaderResult, error) {
	raw, err := hex.DecodeString(messageHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the message is not hex: %w", err)
	}

	message, err := messages.ParsePrivateMessage(mlstls.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("schat: the message does not parse: %w", err)
	}
	if len(message.GroupID) == 0 {
		return nil, fmt.Errorf("schat: the message names no group")
	}

	return &GroupMessageHeaderResult{
		GroupIDHex: hex.EncodeToString(message.GroupID),
		Epoch:      int64(message.Epoch),
	}, nil
}
