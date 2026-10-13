package mobile

import (
	"encoding/hex"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/group"
	"github.com/AyanamiRei-lu/Schat/protocol/mls/messages"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// Joining a group from a Welcome, from the binding.
//
// # Which entry is ours
//
// A Welcome carries one encrypted entry per new member, each sealed to that member's init key,
// and it does not say which is which in a way a recipient can read before decrypting — the
// recipient's identity is inside the ciphertext. So the entries are tried in turn and the one
// that OPENS is ours: HPKE authentication is what identifies it, and an entry addressed to
// somebody else fails to open rather than opening into the wrong secrets.
//
// Trying them is not a weakness. Each attempt either authenticates or does not, and there is no
// way to make another member's entry open without that member's init key.
//
// # The tree comes with the message
//
// AcceptWelcome is given no tree here: it takes the ratchet tree from the GroupInfo's
// ratchet_tree extension, which is the only place a joining member can get one. The tree is
// then checked against the tree_hash in the same GroupInfo, so its provenance does not matter.

// GroupProcessWelcome accepts a Welcome and returns the joining member's state.
//
// initKeyPrivateHex is the value GroupKeyPackage returned alongside the KeyPackage that was
// published. Without it the Welcome cannot be opened, and no amount of retrying will help.
// leafKeyPrivateHex is the private half of the key this member's KeyPackage published, and
// here: without them the member joins with an empty private state, and the symptom is not "I
// have no keys" but a confirmation tag that does not match — because a member without its own
// node keys cannot rebuild the tree the tag was computed over.
func GroupProcessWelcome(welcomeHex, initKeyPrivateHex, leafKeyPrivateHex string) (string, error) {
	suite := crypto.CipherSuite(GroupCipherSuite)

	welcomeBytes, err := hex.DecodeString(welcomeHex)
	if err != nil {
		return "", fmt.Errorf("schat: the Welcome is not hex: %w", err)
	}
	welcome, err := messages.ParseWelcome(mlstls.NewReader(welcomeBytes))
	if err != nil {
		return "", fmt.Errorf("schat: the Welcome does not parse: %w", err)
	}
	if len(welcome.Secrets) == 0 {
		return "", fmt.Errorf("schat: the Welcome carries no entries, so it is addressed to nobody")
	}

	initPrivate, err := hex.DecodeString(initKeyPrivateHex)
	if err != nil {
		return "", fmt.Errorf("schat: the init key is not hex: %w", err)
	}
	if len(initPrivate) == 0 {
		return "", fmt.Errorf("schat: no init key, so no entry of this Welcome can be opened")
	}

	leafPrivate, err := hex.DecodeString(leafKeyPrivateHex)
	if err != nil {
		return "", fmt.Errorf("schat: the leaf key is not hex: %w", err)
	}
	if len(leafPrivate) == 0 {
		return "", fmt.Errorf("schat: no leaf key, so this member would join without the private " +
			"state it needs to follow the group")
	}

	var lastErr error
	for _, entry := range welcome.Secrets {
		joined, err := group.AcceptWelcome(group.AcceptWelcomeSpec{
			Suite:          suite,
			Welcome:        welcome,
			Entry:          entry,
			InitKeyPrivate: initPrivate,
			MyLeafPrivate:  leafPrivate,
			DecryptGroupInfo: func(key, nonce, ciphertext []byte) ([]byte, error) {
				return aesGCMOpen(key, nonce, ciphertext)
			},
		})
		if err != nil {
			// Not addressed to us, or malformed. Keep the reason: if EVERY entry fails, one of
			// those reasons is the real one and the caller needs to see it rather than a bare
			// "no entry opened".
			lastErr = err
			continue
		}

		snapshot, err := joined.Epoch.Snapshot()
		if err != nil {
			return "", err
		}
		return string(snapshot), nil
	}

	return "", fmt.Errorf("schat: no entry of this Welcome could be opened with the init key "+
		"supplied; the last attempt failed with: %w", lastErr)
}
