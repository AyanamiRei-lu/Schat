package tree

import (
	"bytes"
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
)

// Applying an update path whose resolution is FILTERED (RFC 9420 section 7.6).
//
// # The exclusion rule this exists for
//
// Each path secret is encrypted to the resolution of the corresponding copath node — but not
// to every member of it. The specification requires that resolution to EXCLUDE the leaves
// this same commit is adding or removing:
//
//   - a leaf being ADDED receives the epoch through its Welcome; a path secret sent to it
//     would hand key material to a member that is not in the epoch it belongs to;
//   - a leaf being REMOVED must not receive it either, or the removal accomplishes nothing:
//     the member derives the new epoch's keys and keeps reading the group.
//
// The second is the more serious and the easier to miss, because nothing reports it: a
// removed member that leaked a secret looks exactly like a removed member that did not.
//
// # Why a sender needs more than ciphertexts
//
// A receiver recovers path secrets by decrypting them. A SENDER does not decrypt anything — it
// generated them — and the earlier design let it answer only through a map keyed on the
// ciphertexts it had produced. That works until a path node has no ciphertexts at all, which
// is precisely what happens when every member of its copath resolution is excluded: removing
// the last other member from a two-leaf group leaves the root's only recipient excluded, so
// the node carries nothing and the sender had no key to look up. The commit could not be
// created at all.
//
// knownSecrets closes that hole: a caller that already holds a path secret supplies it by NODE
// INDEX, and it is used before the applier is consulted. The applier remains for the ordinary
// case, where a secret has to be decrypted.
func ApplyUpdatePathExcluding(
	t Tree,
	senderLeaf uint32,
	path *UpdatePath,
	excluded map[uint32]bool,
	knownSecrets map[uint32][]byte,
	applier UpdatePathApplier,
	originalHashes [][]byte,
	suite crypto.CipherSuite,
	// commitSecret receives the path secret of the ROOT, which is the commit secret the
	// key schedule consumes. A receiver cannot be given it: it derives it here, while the
	// path is applied, or not at all. It is an out-parameter for the same reason the
	// private-node map is — adding a return value would mean editing every failure return
	// in this function.
	commitSecret *[]byte,
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

		expected := 0
		for _, member := range resolution {
			if !excluded[member] {
				expected++
			}
		}
		if len(updateNode.EncryptedPathSecret) != expected {
			return nil, fmt.Errorf("mls/tree: path node %d carries %d ciphertexts but its filtered "+
				"copath resolution has %d members", node, len(updateNode.EncryptedPathSecret), expected)
		}

		// A secret the caller already holds wins over anything that could be decrypted: the
		// sender generated it, and no ciphertext addressed to somebody else can be better
		// evidence of what it is.
		secret := knownSecrets[node]

		if secret == nil && applier != nil {
			next := 0
			for _, member := range resolution {
				if excluded[member] {
					continue
				}
				if recovered, ok := applier(member, updateNode.EncryptedPathSecret[next]); ok {
					secret = recovered
					break
				}
				next++
			}
		}

		if secret == nil {
			if i == len(filtered)-1 {
				return nil, fmt.Errorf("mls/tree: cannot recover the secret for the root-adjacent "+
					"path node %d: no caller-supplied secret and no ciphertext it could open, so "+
					"no secret below it can be derived either", node)
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

		// The loop walks from the ROOT down to the leaf, so its first iteration is the node
		// whose path secret IS the commit secret.
		if commitSecret != nil && i == len(filtered)-1 {
			*commitSecret = secret
		}

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
				"does not derive; a caller-supplied secret must be the one the path was built from", node)
		}

		secrets[node] = secret
	}

	out := make(Tree, len(t))
	copy(out, t)

	newKeys := make(map[uint32][]byte, len(filtered))
	for i, node := range filtered {
		if out[node] == nil || out[node].Parent == nil {
			return nil, fmt.Errorf("mls/tree: node %d is on the path but is not a parent node", node)
		}
		parent := *out[node].Parent
		parent.EncryptionKey = path.Nodes[i].EncryptionKey
		parent.UnmergedLeaves = nil
		out[node] = &Node{Type: NodeTypeParent, Parent: &parent}
		newKeys[node] = path.Nodes[i].EncryptionKey
	}

	newLeaf := *path.LeafNode
	out[leaf] = &Node{Type: NodeTypeLeaf, Leaf: &newLeaf}

	parentHashes, err := PathParentHashes(t, senderLeaf, newKeys, originalHashes, suite)
	if err != nil {
		return nil, err
	}

	for node, hash := range parentHashes {
		if node == leaf {
			leafCopy := *out[leaf].Leaf
			leafCopy.ParentHash = hash
			leafCopy.Source = LeafNodeSourceCommit
			out[leaf] = &Node{Type: NodeTypeLeaf, Leaf: &leafCopy}
			continue
		}
		parentCopy := *out[node].Parent
		parentCopy.ParentHash = hash
		out[node] = &Node{Type: NodeTypeParent, Parent: &parentCopy}
	}

	// Copath children, whose parent was just given a new key. They are not on the path, but a
	// node's parent hash is a hash of its parent, so the parent's new key invalidates theirs —
	// and a commit that skipped them would be rejected by every member whose leaf hangs below
	// one of them.
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

// ExcludedLeavesForCommit returns the NODES a commit's path must not reach: the leaves it
// removes and the leaves it adds.
//
// Both sides have to derive this identically — the sender to decide who to encrypt to, the
// receiver to know how many ciphertexts to expect — so it is derived in one place.
//
// addedLeaves is the caller's to supply: an Add proposal carries a KeyPackage whose leaf index
// is not known until the caller places it. Removals are read out of the proposals.
func ExcludedLeavesForCommit(payloads []ProposalEffect) map[uint32]bool {
	excluded := map[uint32]bool{}
	for _, p := range payloads {
		if p.RemovedLeaf != nil {
			excluded[2**p.RemovedLeaf] = true
		}
		for _, added := range p.AddedLeaves {
			excluded[2*added] = true
		}
	}
	return excluded
}

// ProposalEffect is the part of a proposal that changes the tree, reduced to what the
// exclusion set needs.
//
// It is a plain struct rather than a proposal type so that this package does not import the
// message layer: the dependency runs the other way, and a cycle would be found only when the
// packages are compiled together.
type ProposalEffect struct {
	// RemovedLeaf is the leaf index a Remove proposal removes.
	RemovedLeaf *uint32

	// AddedLeaves are the leaf indices an Add proposal places.
	AddedLeaves []uint32
}
