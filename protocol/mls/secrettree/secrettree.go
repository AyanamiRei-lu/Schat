// Package secrettree implements the MLS secret tree and the sender ratchets
// (RFC 9420 sections 9, 9.1 and 9.2).
//
// # The derivation, verbatim
//
// Figure 25 — a parent to its children:
//
//	tree_node_[N]_secret
//	        +--> ExpandWithLabel(., "tree", "left",  KDF.Nh) = tree_node_[left(N)]_secret
//	        +--> ExpandWithLabel(., "tree", "right", KDF.Nh) = tree_node_[right(N)]_secret
//
// Figure 26 — a leaf into its two ratchets:
//
//	tree_node_[N]_secret
//	        +--> ExpandWithLabel(., "handshake",   "", KDF.Nh)
//	        +--> ExpandWithLabel(., "application", "", KDF.Nh)
//
// and section 9.1 — a ratchet's j-th generation:
//
//	ratchet_secret[j] --DeriveTreeSecret(., "nonce",  j, AEAD.Nn)--> nonce[j]
//	                  --DeriveTreeSecret(., "key",    j, AEAD.Nk)--> key[j]
//	                  --DeriveTreeSecret(., "secret", j, KDF.Nh)--> ratchet_secret[j+1]
//
// # Four shapes of context, three lengths, and no way to notice a mix-up
//
// The label "tree" carries the literal text "left" or "right" as its CONTEXT — not as its
// label, and not a number. The two ratchet roots carry the empty string. The generation is a
// big-endian uint32 in the context. And the key and nonce use the AEAD's own lengths while
// everything else uses the hash length.
//
// Every one of those is a place where a plausible implementation produces values that are
// deterministic, self-consistent, and agreed with by nobody. The official secret-tree vectors
// are what makes them checkable, which is why this package exists to be checked against them.
//
// # Consumed values must be deleted
//
// Section 9.2 requires a value to be deleted as soon as it is consumed — used to encrypt, or
// successfully decrypted — because keeping it defeats forward secrecy for past messages.
// Unconsumed values may be kept for a while, to let out-of-order messages arrive. This package
// computes values and holds nothing: the caller decides what to keep and is told, in
// Ratchet.SecretAt, that every generation it steps past has been consumed.
package secrettree

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/tree"
)

// Tree is one epoch's secret tree, identified by its root secret.
type Tree struct {
	EncryptionSecret []byte
	Leaves           uint32
	Suite            crypto.CipherSuite
}

// New creates a secret tree for an epoch.
func New(encryptionSecret []byte, leaves uint32, suite crypto.CipherSuite) (*Tree, error) {
	if !tree.IsPowerOfTwo(leaves) {
		return nil, fmt.Errorf("mls/secrettree: %d leaves is not a power of two", leaves)
	}
	if len(encryptionSecret) != suite.HashSize() {
		return nil, fmt.Errorf("mls/secrettree: the encryption secret is %d bytes, want %d",
			len(encryptionSecret), suite.HashSize())
	}
	return &Tree{EncryptionSecret: encryptionSecret, Leaves: leaves, Suite: suite}, nil
}

// NodeSecret returns the secret of a node in the tree.
//
// The tree has the same structure — and the same array indexing — as the ratchet tree, so a
// leaf's secret here and that member's leaf there are the same position. Getting the indexing
// wrong would give a member somebody else's ratchet, and every message it sent would be
// unreadable to everyone including the intended recipient.
func (t *Tree) NodeSecret(node uint32) ([]byte, error) {
	layout, err := tree.NumNodes(t.Leaves)
	if err != nil {
		return nil, err
	}
	if node >= layout {
		return nil, fmt.Errorf("mls/secrettree: node %d is outside a tree of %d nodes", node, layout)
	}

	root, err := tree.Root(t.Leaves)
	if err != nil {
		return nil, err
	}

	// A one-leaf tree's only node IS the root, and a root's secret is the epoch's encryption
	// secret with no derivation between them. DirectPath returns an empty path there, which is
	// correct rather than an error, so the case is handled explicitly.
	if node == root {
		return t.EncryptionSecret, nil
	}

	// The path is taken from the TARGET UPWARDS and then applied in reverse, rather than
	// descending from the root by comparing indices. Descending looks natural and is wrong: a
	// node's subtree is not the range of indices on one side of it, so comparing against a
	// child's index walks into the wrong subtree as soon as the target lies in the right half.
	path, err := tree.DirectPath(node, t.Leaves)
	if err != nil {
		return nil, err
	}
	if len(path) == 0 || path[len(path)-1] != root {
		return nil, fmt.Errorf("mls/secrettree: the path from node %d does not end at the root", node)
	}

	secret := t.EncryptionSecret
	for i := len(path) - 1; i >= 0; i-- {
		parent := path[i]
		child := node
		if i > 0 {
			child = path[i-1]
		}

		left, ok := tree.Left(parent)
		if !ok {
			return nil, fmt.Errorf("mls/secrettree: node %d has no left child", parent)
		}

		// The context is the literal word, not the label: the label is "tree" for both and only
		// the context tells them apart.
		context := "right"
		if child == left {
			context = "left"
		}

		secret, err = crypto.ExpandWithLabel(secret, "tree", []byte(context), t.Suite.HashSize(), t.Suite)
		if err != nil {
			return nil, err
		}
	}

	return secret, nil
}

// Ratchet is one leaf's handshake or application ratchet.
type Ratchet struct {
	// Secret is the ratchet's current secret; its position is Generation.
	Secret     []byte
	Generation uint32
	Suite      crypto.CipherSuite
}

// HandshakeRatchet returns the ratchet a leaf uses for proposals and commits.
func (t *Tree) HandshakeRatchet(leaf uint32) (*Ratchet, error) {
	return t.ratchet(leaf, "handshake")
}

// ApplicationRatchet returns the ratchet a leaf uses for application messages.
//
// The two are separate ratchets rather than one with two labels, and that separation is what
// keeps a nonce from being reused: a member that sent a commit and then a message would
// otherwise draw both from the same sequence.
func (t *Tree) ApplicationRatchet(leaf uint32) (*Ratchet, error) {
	return t.ratchet(leaf, "application")
}

func (t *Tree) ratchet(leaf uint32, which string) (*Ratchet, error) {
	if leaf >= t.Leaves {
		return nil, fmt.Errorf("mls/secrettree: leaf %d is outside a tree of %d leaves", leaf, t.Leaves)
	}

	leafSecret, err := t.NodeSecret(2 * leaf)
	if err != nil {
		return nil, err
	}

	// The ratchet roots carry the EMPTY context; only the label differs.
	root, err := crypto.ExpandWithLabel(leafSecret, which, []byte{}, t.Suite.HashSize(), t.Suite)
	if err != nil {
		return nil, err
	}
	return &Ratchet{Secret: root, Suite: t.Suite}, nil
}

// KeyNonce returns the AEAD key and nonce for the ratchet's current generation.
func (r *Ratchet) KeyNonce() (key, nonce []byte, err error) {
	key, err = crypto.DeriveTreeSecret(r.Secret, "key", r.Generation, r.Suite.AEADKeySize(), r.Suite)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = crypto.DeriveTreeSecret(r.Secret, "nonce", r.Generation, r.Suite.AEADNonceSize(), r.Suite)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// Advance moves the ratchet forward one generation.
//
// Every generation passed is consumed and must not be used again: reusing a key and nonce pair
// is the one thing an AEAD cannot survive, and the caller is the only one who knows whether a
// message was actually sent. This method therefore does not delete anything — it cannot, it
// holds no store — but it is the point at which a caller must.
func (r *Ratchet) Advance() error {
	next, err := crypto.DeriveTreeSecret(r.Secret, "secret", r.Generation, r.Suite.HashSize(), r.Suite)
	if err != nil {
		return err
	}
	r.Secret = next
	r.Generation++
	return nil
}

// KeyNonceAt returns the key and nonce at an arbitrary generation, without moving the ratchet.
//
// A receiver needs this for out-of-order delivery: it may have to decrypt generation 7 after
// generation 9. Stepping forward discards the intermediate secrets, so a caller that needs to
// go back must have kept them — and if it kept them, it has to decide for how long, which is
// the tension section 9.2 describes between forward secrecy and late delivery.
func (r *Ratchet) KeyNonceAt(generation uint32) (key, nonce []byte, err error) {
	if generation < r.Generation {
		return nil, nil, fmt.Errorf("mls/secrettree: generation %d is behind the ratchet at %d; "+
			"its secret has been consumed and cannot be recomputed", generation, r.Generation)
	}

	secret := r.Secret
	for g := r.Generation; g < generation; g++ {
		secret, err = crypto.DeriveTreeSecret(secret, "secret", g, r.Suite.HashSize(), r.Suite)
		if err != nil {
			return nil, nil, err
		}
	}

	key, err = crypto.DeriveTreeSecret(secret, "key", generation, r.Suite.AEADKeySize(), r.Suite)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = crypto.DeriveTreeSecret(secret, "nonce", generation, r.Suite.AEADNonceSize(), r.Suite)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}
