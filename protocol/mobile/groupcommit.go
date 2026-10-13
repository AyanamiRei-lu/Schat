package mobile

import (
	"encoding/hex"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/group"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/tree"
)

// Processing a commit, from the binding.
//
// # A commit is not a message
//
// Application messages travel as PrivateMessage and are opened with an epoch's ratchet. A commit
// travels as an AuthenticatedContent — a PUBLIC message, signed and carrying a confirmation tag
// — and is processed against the epoch's tree. The two share nothing but the word "message", and
// a client that fed one to the other's path would report a decoding failure that describes
// neither.
//
// # Where the member's own key comes from
//
// A receiver decrypts the path secret addressed to it, and it can only do that with the private
// key for ITS leaf. That key is in the epoch's own PrivateNodes — put there when the member
// joined, and replaced by every commit it processes. This function therefore takes no key
// parameter: a caller that supplied one could supply a stale one, and the failure would look
// like a cryptographic problem rather than an out-of-date client.
//
// # What it does not check
//
// It does not verify the sender's signature against a membership decision — it verifies it
// against the key in the tree, which is what the tree is for. Whether that leaf SHOULD be in the
// group is the membership question, and it was answered when the leaf was added.

// GroupProcessCommit applies a commit from another member and returns the new state.
//
// myLeaf is the leaf index of THIS member — the one processing the commit, not the one that
// sent it.
func GroupProcessCommit(stateJSON, commitHex string, myLeaf int64) (string, error) {
	if myLeaf < 0 {
		return "", fmt.Errorf("schat: a leaf index cannot be negative")
	}

	epoch, err := group.RestoreEpoch([]byte(stateJSON))
	if err != nil {
		return "", err
	}

	raw, err := hex.DecodeString(commitHex)
	if err != nil {
		return "", fmt.Errorf("schat: the commit is not hex: %w", err)
	}
	authenticated, err := messages.ParseAuthenticatedContent(mlstls.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("schat: the commit does not parse: %w", err)
	}
	if authenticated.Content.Type != messages.ContentTypeCommit {
		return "", fmt.Errorf("schat: this is a %d, not a commit", authenticated.Content.Type)
	}
	if authenticated.Content.Sender.Type != messages.SenderTypeMember {
		return "", fmt.Errorf("schat: the commit does not come from a member")
	}

	senderLeaf := authenticated.Content.Sender.LeafIndex
	if int(2*senderLeaf) >= len(epoch.Tree) || epoch.Tree[2*senderLeaf] == nil ||
		epoch.Tree[2*senderLeaf].Leaf == nil {
		return "", fmt.Errorf("schat: the commit claims leaf %d, which holds no member", senderLeaf)
	}
	senderKey := epoch.Tree[2*senderLeaf].Leaf.SignatureKey

	contextBytes, err := epoch.Context.Marshal()
	if err != nil {
		return "", err
	}

	// The applier decrypts the path secret addressed to this member, using the key this member
	// currently holds. If a commit has moved that key and the client has not processed it, the
	// decryption fails — which is the correct outcome: this member is behind, and saying so beats
	// deriving keys from a tree it no longer shares.
	applier := func(_ uint32, ct tree.HPKECiphertext) ([]byte, bool) {
		leafKey := epoch.PrivateNodes[2*uint32(myLeaf)]
		if len(leafKey) == 0 {
			return nil, false
		}
		secret, err := crypto.DecryptWithLabel(leafKey, "UpdatePathNode", contextBytes,
			ct.KemOutput, ct.Ciphertext, epoch.Suite)
		if err != nil {
			return nil, false
		}
		return secret, true
	}

	next, err := epoch.ProcessCommit(group.CommitInput{
		WireFormat:         authenticated.WireFormat,
		Content:            &authenticated.Content,
		Signature:          authenticated.Auth.Signature,
		ConfirmationTag:    authenticated.Auth.ConfirmationTag,
		SenderSignatureKey: senderKey,
		Applier:            applier,
		MyLeaf:             uint32(myLeaf),
	})
	if err != nil {
		return "", fmt.Errorf("schat: the commit was refused: %w", err)
	}

	snapshot, err := next.Snapshot()
	if err != nil {
		return "", err
	}
	return string(snapshot), nil
}
