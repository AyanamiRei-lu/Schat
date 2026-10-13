package tree

import (
	"fmt"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
	mlstls "github.com/AyanamiRei-lu/Schat/protocol/mls/tls"
)

// The parent hash chain along an updated path (RFC 9420 section 7.9).
//
// # Why this cannot be read off the tree
//
// ParentHash reads a node's key and its own parent hash out of the tree. During an update
// neither is in the tree yet: the keys on the path are being replaced, and the parent hashes
// depend on each other, so they have to be built in one pass from the ROOT DOWNWARDS:
//
//   - the root's parent hash is the zero-length string, which is what terminates the chain;
//   - every other node's parent hash is
//         Hash{ parent's NEW public key, parent's parent hash, tree hash of its sibling }
//     where the sibling's tree hash comes from the tree as it stood BEFORE the update.
//
// The copath subtrees are not touched by the update, so their hashes are the same before and
// after — which is exactly why the specification names the field "original".
//
// # The order is the whole difficulty
//
// Computing these leaf-first produces values that look right, are self-consistent, and are
// rejected by every other member: each node's hash would be built on a parent hash that the
// parent itself has not computed yet. The loop below therefore walks the path in reverse and
// reads the parent's result, not its stored value.

// parentHashValue is the hash of one ParentHashInput.
//
// It takes the three field values explicitly rather than a node, because during an update the
// key and the parent hash are the NEW ones and exist nowhere in the tree yet.
func parentHashValue(encryptionKey, parentHash, originalSiblingTreeHash []byte, suite crypto.CipherSuite) ([]byte, error) {
	w := mlstls.NewWriter(len(encryptionKey) + len(parentHash) + len(originalSiblingTreeHash) + 12)
	w.Opaque(encryptionKey)
	w.Opaque(parentHash)
	w.Opaque(originalSiblingTreeHash)
	if err := w.Err(); err != nil {
		return nil, err
	}
	return suite.Hash(w.Bytes()), nil
}

// PathParentHashes computes the new parent hash of every node on an updated path, including
// the leaf itself.
//
// newKeys maps node index to the node's NEW HPKE public key; every node of the filtered
// direct path must be present. originalHashes holds the tree hash of every node before the
// update. The result maps node index to the parent hash that node must store afterwards.
func PathParentHashes(
	t Tree,
	leafIndex uint32,
	newKeys map[uint32][]byte,
	originalHashes [][]byte,
	suite crypto.CipherSuite,
) (map[uint32][]byte, error) {
	if len(originalHashes) != len(t) {
		return nil, fmt.Errorf("mls/tree: %d original tree hashes for %d nodes",
			len(originalHashes), len(t))
	}

	leaf := 2 * leafIndex
	if int(leaf) >= len(t) {
		return nil, fmt.Errorf("mls/tree: leaf %d is outside a tree of %d nodes", leafIndex, len(t))
	}

	leaves, err := LeavesForLayout(uint32(len(t)))
	if err != nil {
		return nil, err
	}

	path, err := FilteredDirectPath(t, leaf)
	if err != nil {
		return nil, err
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("mls/tree: leaf %d has no non-blank node above it", leafIndex)
	}

	root := path[len(path)-1]
	out := make(map[uint32][]byte, len(path)+1)

	// The root terminates the chain with a zero-length hash.
	out[root] = []byte{}

	// Then downwards: each node's parent hash covers the parent's NEW key and the parent hash
	// the parent has just been given.
	for i := len(path) - 2; i >= 0; i-- {
		node := path[i]
		parent := path[i+1]

		parentKey, ok := newKeys[parent]
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d is on the path but has no new key", parent)
		}
		parentHash, ok := out[parent]
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d's parent hash was not computed before its child's", parent)
		}

		sibling, ok := Sibling(node, leaves)
		if !ok {
			return nil, fmt.Errorf("mls/tree: node %d has no sibling", node)
		}
		if int(sibling) >= len(originalHashes) {
			return nil, fmt.Errorf("mls/tree: sibling %d has no original tree hash", sibling)
		}

		value, err := parentHashValue(parentKey, parentHash, originalHashes[sibling], suite)
		if err != nil {
			return nil, err
		}
		out[node] = value
	}

	// Finally the leaf, whose parent is the first node of the path.
	first := path[0]
	firstKey, ok := newKeys[first]
	if !ok {
		return nil, fmt.Errorf("mls/tree: node %d is on the path but has no new key", first)
	}
	firstHash, ok := out[first]
	if !ok {
		return nil, fmt.Errorf("mls/tree: the first path node's parent hash was not computed")
	}

	sibling, ok := Sibling(leaf, leaves)
	if !ok {
		return nil, fmt.Errorf("mls/tree: leaf %d has no sibling", leafIndex)
	}
	if int(sibling) >= len(originalHashes) {
		return nil, fmt.Errorf("mls/tree: sibling %d has no original tree hash", sibling)
	}

	leafHash, err := parentHashValue(firstKey, firstHash, originalHashes[sibling], suite)
	if err != nil {
		return nil, err
	}
	out[leaf] = leafHash

	return out, nil
}
