package tree

import (
	"fmt"

	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// The ratchet tree extension (RFC 9420 section 12.4.3.3).
//
//	struct {
//	    ExtensionType extension_type;   /* ratchet_tree = 0x0002 */
//	    opaque tree<V>;                 /* the tree, as the optional<Node> vector */
//	} RatchetTreeExtension;
//
// # Why a new member cannot do without it
//
// A Welcome delivers the group's SECRETS and its GroupInfo — the context, the confirmation tag,
// the signer — but none of that says WHO IS IN THE GROUP. The ratchet tree does, and a member
// that accepted a Welcome without one would hold the epoch's keys and have no idea whose
// messages those keys are supposed to open, or which leaves to encrypt to.
//
// The specification puts the tree in a GroupInfo extension precisely so that no second channel
// is needed, and calls it ratchet_tree. It is public data: every member already has it, and a
// member that received it from an untrusted source can check it, because the tree must hash to
// the tree_hash in the GroupInfo it arrived with. That check is what this file makes possible
// and what AcceptWelcome performs.
//
// # The encoding is the one that was verified
//
// The tree travels as the same `optional<Node>` vector that tree.MarshalTree produces and
// ParseTree reads — the format checked against 98 official trees byte for byte. Wrapping it in
// an extension must not introduce a second encoding of a ratchet tree.

// ExtensionTypeRatchetTree is the identifier of the ratchet tree extension.
const ExtensionTypeRatchetTree uint16 = 0x0002

// RatchetTreeExtension wraps a tree for a GroupInfo's extensions.
func RatchetTreeExtension(t Tree) (Extension, error) {
	if len(t) == 0 {
		return Extension{}, fmt.Errorf("mls/tree: no tree to put in an extension")
	}

	encoded, err := MarshalTree(t)
	if err != nil {
		return Extension{}, err
	}
	return Extension{Type: ExtensionTypeRatchetTree, Data: encoded}, nil
}

// RatchetTreeFromExtension reads the tree out of an extension.
//
// It refuses an extension of another type rather than trying to interpret its bytes: a caller
// that grabbed the wrong extension would otherwise get either a parse error that says nothing
// or, worse, a tree decoded from somebody else's data.
func RatchetTreeFromExtension(e Extension) (Tree, error) {
	if e.Type != ExtensionTypeRatchetTree {
		return nil, fmt.Errorf("mls/tree: extension type %#04x is not a ratchet tree", e.Type)
	}
	if len(e.Data) == 0 {
		return nil, fmt.Errorf("mls/tree: the ratchet tree extension is empty")
	}

	t, err := ParseTree(mlstls.NewReader(e.Data))
	if err != nil {
		return nil, fmt.Errorf("mls/tree: decoding the tree from the extension: %w", err)
	}
	return t, nil
}

// FindRatchetTree returns the ratchet tree from a list of extensions.
//
// A GroupInfo may carry several extensions, and the one that matters here is identified by its
// type rather than by its position — the order of extensions is not something a receiver may
// rely on.
func FindRatchetTree(extensions []Extension) (Tree, bool, error) {
	for _, e := range extensions {
		if e.Type != ExtensionTypeRatchetTree {
			continue
		}
		t, err := RatchetTreeFromExtension(e)
		if err != nil {
			return nil, true, err
		}
		return t, true, nil
	}
	return nil, false, nil
}
