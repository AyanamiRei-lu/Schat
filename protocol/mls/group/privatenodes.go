package group

import (
	"fmt"

	"github.com/schat/schat/protocol/mls/crypto"
	"github.com/schat/schat/protocol/mls/tree"
)

// The private keys along a member's own direct path (RFC 9420 section 12.4.3.1).
//
// # Why this is one function and not two
//
// Two situations produce these keys, and the derivation in both is identical:
//
//   - a member JOINING through a Welcome, which delivers the path secret of the lowest common
//     ancestor between it and the committer;
//   - a member PROCESSING a commit, which decrypts the path secret addressed to it in the
//     update path.
//
// Writing the derivation twice would be the fourth time this project has kept one rule in two
// places — after the exclusion set, the proposal effects and the original tree hashes — and each
// of those ended with the two copies disagreeing. The welcome path and the commit path must
// produce the same keys, because they describe the same tree.
//
// # The one step that is easy to get wrong
//
// The delivered secret has ALREADY been through the "path" derivation. The committer derives and
// then records, so what travels is the ancestor's own path secret, not its parent's. This
// function therefore starts at "node" and only steps "path" for the nodes ABOVE the ancestor.
//
// Doing an extra "path" step would shift the chain by one node, and the member would hold a
// parent's key under a child's index. Nothing would fail at the moment of joining — it would
// fail at the next commit, as an inability to decrypt a secret addressed to it, which looks like
// a cryptographic problem and is an off-by-one.

// derivePrivateNodes returns the private key of every node on myLeaf's direct path.
//
// myLeafPrivate is the private half of the key the leaf publishes; it is the member's own key
// and is set on the leaf itself. pathSecret may be nil — a commit with no path delivers none,
// and a member then holds only the keys it can already reach.
func derivePrivateNodes(
	t tree.Tree,
	myLeaf uint32,
	committerLeaf uint32,
	myLeafPrivate []byte,
	pathSecret []byte,
	suite crypto.CipherSuite,
) (map[uint32][]byte, error) {
	nodes := map[uint32][]byte{}

	if len(myLeafPrivate) > 0 {
		nodes[2*myLeaf] = myLeafPrivate
	}
	if len(pathSecret) == 0 {
		return nodes, nil
	}

	leaves := uint32((len(t) + 1) / 2)

	ancestor, ok, err := tree.LowestCommonAncestor(2*myLeaf, 2*committerLeaf, leaves)
	if err != nil {
		return nil, err
	}
	if !ok {
		// Two leaves of the same tree always share a node above them, so this is a structural
		// failure rather than a peer's fault.
		return nil, fmt.Errorf("mls/group: leaves %d and %d share no node above them", myLeaf, committerLeaf)
	}

	// The ancestor's own key. The secret as delivered is already the ancestor's path secret.
	nodeSecret, err := crypto.DeriveSecret(pathSecret, "node", suite)
	if err != nil {
		return nil, err
	}
	nodes[ancestor] = nodeSecret

	// Its ancestors, one "path" step each. The walk is taken from MY LEAF's direct path rather
	// than by asking for the ancestor's, because the leaf's path is the one whose behaviour is
	// covered by the tree vectors; the entries after the ancestor are the nodes above it, up to
	// the root.
	path, err := tree.DirectPath(2*myLeaf, leaves)
	if err != nil {
		return nil, err
	}

	above := false
	for _, node := range path {
		if node == ancestor {
			above = true
			continue
		}
		if !above {
			continue
		}

		pathSecret, err = crypto.DeriveSecret(pathSecret, "path", suite)
		if err != nil {
			return nil, err
		}
		nodeSecret, err = crypto.DeriveSecret(pathSecret, "node", suite)
		if err != nil {
			return nil, err
		}
		nodes[node] = nodeSecret
	}

	return nodes, nil
}
