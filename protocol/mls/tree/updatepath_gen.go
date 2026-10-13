package tree

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// UpdatePath generation (RFC 9420 sections 7.5 and 7.6).
//
// The chains, from the specification text:
//
//	path_secret[n] = DeriveSecret(path_secret[n-1], "path")
//	node_secret[n] = DeriveSecret(path_secret[n], "node")
//	node_priv[n], node_pub[n] = KEM.DeriveKeyPair(node_secret[n])
//
// and each path secret is delivered to the members of the corresponding copath resolution:
//
//	(kem_output, ciphertext) = EncryptWithLabel(node_public_key, "UpdatePathNode",
//	                                            group_context, path_secret)
//
// # What is deliberately not here yet
//
// The function below builds the path secrets, the new node keys and the ciphertexts. It does
// NOT yet compute the new parent hashes for the path, which the committer must also do
// before the tree is consistent — ParentHash exists and is verified in part, but the walk
// that assigns the results along a freshly generated path is not written.
//
// That omission is stated here rather than left as a TODO because the difference matters:
// a caller that used this function and stopped would produce a tree whose parent hashes are
// stale, and the members receiving it would reject the commit for a reason that looks
// unrelated to the code that was missing.

// UpdatePathResult is a generated update path plus what the committer needs to update its
// own copy of the tree.
type UpdatePathResult struct {
	Path *UpdatePath

	// FilteredPath holds the node indices the path covers, leaf-first, with blanks removed.
	// The order is the wire order: nodes[i] belongs to FilteredPath[i].
	FilteredPath []uint32

	// PathSecrets holds one secret per entry of FilteredPath.
	PathSecrets [][]byte

	// NodePrivateKeys maps a node index on the path to that node's HPKE private key. It is the
	// generator's LOCAL private state: the path secrets and the node keys derived from them are
	// what let this member follow the commits that come after its own.
	//
	// The generator already computed these — a node key pair cannot be published without them —
	// and an earlier version dropped them. The consequence was a member that could produce a
	// commit and could not process anybody else's, which is a failure no sender-driven test can
	// see.
	NodePrivateKeys map[uint32][]byte
}

// GenerateUpdatePath builds an update path for a leaf.
//
// initialPathSecret is the fresh randomness the caller supplies (KDF.Nh bytes); it becomes
// the leaf's own path secret, from which every secret on the path is derived.
//
// excludedNodes lists nodes that must not receive a path secret — in a commit that adds
// members, that is the new leaves, which learn the epoch secrets through the Welcome
// instead. Passing them here is not optional: a path secret sent to a member who is not in
// the epoch it belongs to is a disclosure, not a bug in bookkeeping.
func GenerateUpdatePath(
	t Tree,
	leafIndex uint32,
	groupContext []byte,
	initialPathSecret []byte,
	excludedNodes []uint32,
	suite crypto.CipherSuite,
) (*UpdatePathResult, error) {
	node := 2 * leafIndex
	if int(node) >= len(t) {
		return nil, fmt.Errorf("mls/tree: leaf %d is outside a tree of %d nodes", leafIndex, len(t))
	}
	if len(initialPathSecret) != suite.HashSize() {
		return nil, fmt.Errorf("mls/tree: the initial path secret is %d bytes, want %d",
			len(initialPathSecret), suite.HashSize())
	}

	filtered, err := FilteredDirectPath(t, node)
	if err != nil {
		return nil, err
	}
	if len(filtered) == 0 {
		// A sender with no non-blank node above it has nothing to update, and that is not an
		// error — it is what a one-member group's first commit looks like. Such a group is a
		// single node; adding a member extends the tree with a BLANK root, so the sender's own
		// direct path is entirely blank.
		//
		// Section 12.4.1 covers the case: the commit's path field is the NULL OPTIONAL — not an
		// empty path, which encodes differently — and the commit secret is the all-zero vector
		// of KDF.Nh. An empty result says exactly that, and the caller turns it into those two
		// things.
		//
		// Refusing here made a legal Add impossible, and it failed with an error about trees
		// rather than about what the caller was trying to do.
		return &UpdatePathResult{Path: nil, FilteredPath: nil, PathSecrets: nil}, nil
	}

	excluded := make(map[uint32]bool, len(excludedNodes))
	for _, n := range excludedNodes {
		excluded[n] = true
	}

	result := &UpdatePathResult{
		Path:         &UpdatePath{},
		FilteredPath: filtered,
		PathSecrets:  make([][]byte, 0, len(filtered)),

		NodePrivateKeys: make(map[uint32][]byte, len(filtered)),
	}

	// The commit's new leaf: for a self-update it is the updated leaf itself, so its
	// encryption key is the one derived for the leaf's own position. That key is the
	// caller's business (it is part of the LeafNode it signed), so it is taken from the
	// tree the caller passes in and re-used verbatim here.
	if t[node] == nil || t[node].Leaf == nil {
		return nil, fmt.Errorf("mls/tree: leaf %d is blank; its new leaf node must be supplied "+
			"by the caller before an update path can be generated", leafIndex)
	}
	result.Path.LeafNode = t[node].Leaf

	pathSecret := initialPathSecret
	child := node

	for _, pathNode := range filtered {
		pathSecret, err = crypto.DeriveSecret(pathSecret, "path", suite)
		if err != nil {
			return nil, err
		}
		result.PathSecrets = append(result.PathSecrets, pathSecret)

		nodeSecret, err := crypto.DeriveSecret(pathSecret, "node", suite)
		if err != nil {
			return nil, err
		}
		// Kept, not discarded: this is the private half of the node the commit is about to
		// publish.
		result.NodePrivateKeys[pathNode] = nodeSecret

		_, publicKey, err := crypto.DeriveKeyPair(nodeSecret, suite)
		if err != nil {
			return nil, err
		}

		// The copath node for this step is the sibling of the node BELOW the path node —
		// the sibling of the leaf itself on the first step. Getting this off by one hands
		// the secret to the wrong subtree, and the cryptography cannot notice.
		copath, ok := Sibling(child, uint32((len(t)+1)/2))
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d has no sibling", child)
		}

		resolution, err := Resolution(t, copath)
		if err != nil {
			return nil, err
		}

		updateNode := UpdatePathNode{EncryptionKey: publicKey}

		for _, member := range resolution {
			if excluded[member] {
				continue
			}
			recipientKey, err := encryptionKeyOf(t, member)
			if err != nil {
				return nil, err
			}

			kemOutput, ciphertext, err := crypto.EncryptWithLabel(
				recipientKey, "UpdatePathNode", groupContext, pathSecret, suite)
			if err != nil {
				return nil, fmt.Errorf("mls/tree: encrypting to node %d: %w", member, err)
			}
			updateNode.EncryptedPathSecret = append(updateNode.EncryptedPathSecret,
				HPKECiphertext{KemOutput: kemOutput, Ciphertext: ciphertext})
		}

		result.Path.Nodes = append(result.Path.Nodes, updateNode)
		child = pathNode
	}

	return result, nil
}

// encryptionKeyOf returns the HPKE public key held by a node.
func encryptionKeyOf(t Tree, node uint32) ([]byte, error) {
	if int(node) >= len(t) || t[node] == nil {
		return nil, fmt.Errorf("mls/tree: node %d is blank and holds no key", node)
	}
	if t[node].Leaf != nil {
		return t[node].Leaf.EncryptionKey, nil
	}
	if t[node].Parent != nil {
		return t[node].Parent.EncryptionKey, nil
	}
	return nil, fmt.Errorf("mls/tree: node %d holds neither a leaf nor a parent", node)
}
