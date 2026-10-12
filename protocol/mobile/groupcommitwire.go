package mobile

import (
	"encoding/hex"
	"fmt"

	"github.com/schat/schat/protocol/mls/group"
	"github.com/schat/schat/protocol/mls/messages"
	mlstls "github.com/schat/schat/protocol/mls/tls"
)

// Commits on the relay, and the one question a client must answer before it can process one.
//
// # Why a commit needs its own content type
//
// The four types already in use each go somewhere different:
//
//	0x01  a one-to-one frame        -> the peer's mailbox
//	0x02  a one-to-one handshake    -> the peer's mailbox
//	0x03  a group message           -> the GROUP's mailboxes, derived from the epoch
//	0x04  a group welcome           -> the JOINER's identity mailbox, because it is not yet in
//	                                   the group and cannot derive the group's mailboxes
//	0x05  a group commit            -> the GROUP's mailboxes, like a message
//
// A commit travels with the group because only members can apply it, and the members are exactly
// the people who can derive those mailboxes. It is not a message: it is an AuthenticatedContent
// that replaces the epoch, and a client that fed it to the message path would try to open it with
// a ratchet it does not have.
//
// # Why the type byte matters more here than anywhere
//
// A client that treated a commit as a message would fail to parse it. A client that treated a
// WELCOME as a commit would try to apply a group it is not in. And a client that treated a
// commit as a welcome would try to join a group it is already in — which is exactly the mistake
// the two types exist to make impossible.

// ContentTypeGroupCommit is the envelope content type of an MLS commit.
const ContentTypeGroupCommit = 0x05

// WrapGroupCommit puts a commit into a relay envelope for a delivery token.
//
// The token is one of the GROUP's mailboxes: a commit is addressed to the members, who are the
// only parties that can apply it.
func WrapGroupCommit(tokenHex string, commit []byte) ([]byte, error) {
	wire, err := WrapGroup(tokenHex, commit)
	if err != nil {
		return nil, err
	}
	wire[16] = ContentTypeGroupCommit
	return wire, nil
}

// UnwrapGroupCommit reads a commit out of an envelope.
func UnwrapGroupCommit(wire []byte) ([]byte, error) {
	if len(wire) < 18 {
		return nil, fmt.Errorf("schat: an envelope needs a 16-byte token, a type and a payload; "+
			"this one is %d bytes", len(wire))
	}
	if wire[16] != ContentTypeGroupCommit {
		return nil, fmt.Errorf("schat: envelope content type %#02x is not a group commit", wire[16])
	}
	return wire[17:], nil
}

// GroupMyLeaf returns the leaf index this identity occupies in the group.
//
// A member cannot process a commit without it: the leaf index decides which private key it
// decrypts a path secret with, and a member that used the wrong one would decrypt a secret
// addressed to somebody else and then rebuild a tree that is not the group's. The failure would
// appear at the confirmation tag, which says nothing about the cause.
//
// It is exported rather than left internal because the CLIENT has to store it: every later call
// needs it, and asking the client to guess — as the tests did before this existed — is asking
// for exactly that class of mistake.
func GroupMyLeaf(stateJSON, identityJSON string) (int64, error) {
	identity, err := IdentityFromJSON(identityJSON)
	if err != nil {
		return -1, err
	}
	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return -1, err
	}
	leaf, err := findMyLeaf(epoch, identity)
	if err != nil {
		return -1, err
	}
	return int64(leaf), nil
}

// GroupCommitSummary describes what a commit would do, for a client that wants to look before it
// applies one.
type GroupCommitSummary struct {
	// SenderLeaf is the member that made the commit.
	SenderLeaf int64

	// Epoch is the epoch the commit OPENS — the receiver's current epoch plus one.
	Epoch int64
}

// GroupInspectCommit reads a commit's public header without applying it.
func GroupInspectCommit(commitHex string) (*GroupCommitSummary, error) {
	raw, err := hex.DecodeString(commitHex)
	if err != nil {
		return nil, fmt.Errorf("schat: the commit is not hex: %w", err)
	}
	authenticated, err := messages.ParseAuthenticatedContent(mlstls.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return &GroupCommitSummary{
		SenderLeaf: int64(authenticated.Content.Sender.LeafIndex),
		Epoch:      int64(authenticated.Content.Epoch),
	}, nil
}
