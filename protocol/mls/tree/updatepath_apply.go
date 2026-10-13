package tree

import (
	"bytes"
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// Applying an UpdatePath (receiver side, RFC 9420 section 7.6).
//
// # The shape of the problem
//
// The sender walked the filtered direct path and encrypted each node's path secret to that
// step's copath resolution. A receiver must recover those secrets, and it does so in the
// opposite direction — from the ROOT DOWNWARDS — because there are two ways to learn a
// secret and only one of them is available at each step:
//
//   - if the receiver is a member of that step's copath resolution, it holds a private key
//     that opens the corresponding ciphertext;
//   - otherwise it derives the secret from the one it recovered for the node above, with
//     path_secret[n] = DeriveSecret(path_secret[n-1], "path").
//
// Only the first step the receiver can open needs the first method; every step below it is
// the second. That is why processing runs top-down and why a receiver that walks the path
// the other way cannot work at all, however correct its decryption is.
//
// # Key material is supplied, not stored
//
// This package holds no private keys — it is tree arithmetic. The caller therefore passes a
// decrypt callback that answers one question: "for resolution member m, does this ciphertext
// open with a key I hold, and if so what is the secret?" A caller that holds no key for a
// member answers no, and the derivation path takes over. That keeps the decision about which
// keys exist where it belongs, in the group state, while the tree keeps only the shape.

// UpdatePathApplier answers whether it can open one ciphertext.
//
// member is the tree node the ciphertext was addressed to, which is what identifies the key
// to try. It must not guess: returning a secret it did not decrypt would be indistinguishable
// from a working implementation until the epoch keys failed to agree.
type UpdatePathApplier func(member uint32, ciphertext HPKECiphertext) (secret []byte, ok bool)

// ApplyUpdatePath checks an update path against a tree and returns the updated tree.
//
// The returned tree is a shallow copy with the sender's leaf and every path node replaced;
// the input is left untouched, so a caller that rejects the result — because a later
// validation step failed — has not damaged the state it was validating against.
//
// originalHashes must be the tree hashes of the tree BEFORE this update, indexed by node.
// They are needed for the parent hash chain and cannot be recomputed afterwards, which is
// why the caller passes them rather than this function deriving them from its input: for a
// commit that also adds or removes leaves, those hashes describe a tree that no longer
// exists anywhere by the time the path is processed.
func ApplyUpdatePath(
	t Tree,
	senderLeaf uint32,
	path *UpdatePath,
	applier UpdatePathApplier,
	originalHashes [][]byte,
	suite crypto.CipherSuite,
) (Tree, error) {
	if path == nil || path.LeafNode == nil {
		return nil, fmt.Errorf("mls/tree: the update path carries no leaf node")
	}
	if len(originalHashes) != len(t) {
		return nil, fmt.Errorf("mls/tree: %d original tree hashes for %d nodes",
			len(originalHashes), len(t))
	}

	leaf := 2 * senderLeaf
	if int(leaf) >= len(t) {
		return nil, fmt.Errorf("mls/tree: leaf %d is outside a tree of %d nodes", senderLeaf, len(t))
	}

	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return nil, err
	}

	filtered, err := FilteredDirectPath(t, leaf)
	if err != nil {
		return nil, err
	}
	if len(path.Nodes) != len(filtered) {
		return nil, fmt.Errorf("mls/tree: the update path has %d nodes but the filtered direct "+
			"path of leaf %d has %d", len(path.Nodes), senderLeaf, len(filtered))
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("mls/tree: leaf %d has no node above it to update", senderLeaf)
	}

	secrets := make(map[uint32][]byte, len(filtered))

	// Top-down: the root first, because every other secret is either opened directly or
	// derived from the one above.
	for i := len(filtered) - 1; i >= 0; i-- {
		node := filtered[i]
		updateNode := path.Nodes[i]

		below := leaf
		if i > 0 {
			below = filtered[i-1]
		}
		copath, ok := Sibling(below, leaves)
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d has no sibling", below)
		}
		resolution, err := Resolution(t, copath)
		if err != nil {
			return nil, err
		}
		if len(updateNode.EncryptedPathSecret) != len(resolution) {
			return nil, fmt.Errorf("mls/tree: path node %d carries %d ciphertexts but its copath "+
				"resolution has %d members", node, len(updateNode.EncryptedPathSecret), len(resolution))
		}

		var secret []byte
		if applier != nil {
			for j, member := range resolution {
				if recovered, ok := applier(member, updateNode.EncryptedPathSecret[j]); ok {
					secret = recovered
					break
				}
			}
		}

		if secret == nil {
			// Not a member of this resolution: the secret is the child of the one above.
			if i == len(filtered)-1 {
				return nil, fmt.Errorf("mls/tree: cannot recover the secret for the root-adjacent "+
					"path node %d, so no secret below it can be derived either", node)
			}
			parentSecret, ok := secrets[filtered[i+1]]
			if !ok {
				return nil, fmt.Errorf("mls/tree: node %d's secret is not available", filtered[i+1])
			}
			secret, err = crypto.DeriveSecret(parentSecret, "path", suite)
			if err != nil {
				return nil, err
			}
		}

		// Verify before trusting: the published key must be the one this secret derives, or
		// the sender is claiming a key it does not hold the secret for.
		nodeSecret, err := crypto.DeriveSecret(secret, "node", suite)
		if err != nil {
			return nil, err
		}
		_, derivedPub, err := crypto.DeriveKeyPair(nodeSecret, suite)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(derivedPub, updateNode.EncryptionKey) {
			return nil, fmt.Errorf("mls/tree: path node %d publishes a key that its path secret "+
				"does not derive", node)
		}

		secrets[node] = secret
	}

	// Build the new tree only after every secret has been checked, so a rejected path leaves
	// no partially applied state behind.
	out := make(Tree, len(t))
	copy(out, t)

	newKeys := make(map[uint32][]byte, len(filtered))
	for i, node := range filtered {
		if out[node] == nil || out[node].Parent == nil {
			return nil, fmt.Errorf("mls/tree: node %d is on the path but is not a parent node", node)
		}
		parent := *out[node].Parent
		parent.EncryptionKey = path.Nodes[i].EncryptionKey

		// The update replaces the node's key, so leaves that were unmerged beneath it are
		// merged: their keys are covered by the new one.
		parent.UnmergedLeaves = nil

		out[node] = &Node{Type: NodeTypeParent, Parent: &parent}
		newKeys[node] = path.Nodes[i].EncryptionKey
	}

	// The sender's new leaf node replaces its old one. Its parent_hash is filled in below.
	newLeaf := *path.LeafNode
	out[leaf] = &Node{Type: NodeTypeLeaf, Leaf: &newLeaf}

	parentHashes, err := PathParentHashes(t, senderLeaf, newKeys, originalHashes, suite)
	if err != nil {
		return nil, err
	}

	for node, hash := range parentHashes {
		switch {
		case node == leaf:
			leafCopy := *out[leaf].Leaf
			leafCopy.ParentHash = hash
			// A leaf created by an update or a commit carries its parent hash in the
			// leaf_node_source field, not as a separate value.
			leafCopy.Source = LeafNodeSourceCommit
			out[leaf] = &Node{Type: NodeTypeLeaf, Leaf: &leafCopy}
		default:
			parentCopy := *out[node].Parent
			parentCopy.ParentHash = hash
			out[node] = &Node{Type: NodeTypeParent, Parent: &parentCopy}
		}
	}

	// The copath children, which are NOT on the path but whose parent was just given a new
	// key. A node's parent hash is a hash of its parent, so changing the parent's key
	// invalidates every one of its children's hashes — including the children the update did
	// not otherwise touch.
	//
	// This was missing at first and the end-to-end test caught it: the applied tree failed to
	// verify at a node nowhere near the sender's path. Left in, it would have made every
	// commit in a real group fail on half its members, and the symptom — a parent hash
	// mismatch — would not have pointed at the missing step.
	//
	// Only non-blank copath children are stamped. If the copath child is blank its subtree
	// holds no key this update changed, so its descendants' chains are unaffected; that case
	// is not exercised by the tests here either, which is worth remembering rather than
	// assuming.
	onPath := make(map[uint32]bool, len(filtered)+1)
	for _, node := range filtered {
		onPath[node] = true
	}
	onPath[leaf] = true

	for i, node := range filtered {
		left, leftOK := Left(node)
		right, rightOK := Right(node)
		if !leftOK || !rightOK {
			return nil, fmt.Errorf("mls/tree: updated node %d has no children", node)
		}

		for _, child := range []uint32{left, right} {
			if onPath[child] || int(child) >= len(out) || out[child] == nil {
				continue
			}

			sibling, ok := Sibling(child, leaves)
			if !ok {
				return nil, fmt.Errorf("mls/tree: copath child %d has no sibling", child)
			}
			if int(sibling) >= len(originalHashes) {
				return nil, fmt.Errorf("mls/tree: sibling %d has no original tree hash", sibling)
			}

			value, err := parentHashValue(path.Nodes[i].EncryptionKey, parentHashes[node],
				originalHashes[sibling], suite)
			if err != nil {
				return nil, err
			}

			if out[child].Leaf != nil {
				leafCopy := *out[child].Leaf
				leafCopy.ParentHash = value
				out[child] = &Node{Type: NodeTypeLeaf, Leaf: &leafCopy}
			} else {
				parentCopy := *out[child].Parent
				parentCopy.ParentHash = value
				out[child] = &Node{Type: NodeTypeParent, Parent: &parentCopy}
			}
		}
	}

	return out, nil
}
