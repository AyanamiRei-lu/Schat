package tree

import "fmt"

// The lowest common ancestor of two leaves (RFC 9420 section 12.4.2).
//
// A commit that adds a member must hand that member the path secret of the LOWEST node lying on
// the direct paths of both the committer and the new member. That node is the deepest point at
// which the new member's own subtree meets the committer's, and it is the only path secret the
// new member cannot derive on its own — everything above it is derivable from it, and
// everything below it is its own.
//
// # Why this walks instead of computing
//
// The array layout admits a closed-form expression for the common ancestor, in terms of the
// highest differing bit of the two leaf indices. That expression is compact, fast and easy to
// get subtly wrong — and a wrong value here does not fail loudly: it hands the new member a
// secret for a node it cannot use, and the failure appears later as a member that cannot read
// the group.
//
// The walk below states the DEFINITION instead: the lowest node that appears on both direct
// paths. Its correctness is therefore not something to be checked against a formula, and the
// cost — a few steps, once per new member per commit — is not worth the risk of the shorter
// form.

// LowestCommonAncestor returns the lowest node on the direct paths of both leaves.
//
// a and b are NODE indices of leaves (even), and n is the tree's leaf count. When both are the
// same leaf the leaf itself is returned: it is trivially on both paths, and a member that
// commits for itself is in exactly that position.
func LowestCommonAncestor(a, b, n uint32) (uint32, bool, error) {
	if !IsPowerOfTwo(n) {
		return 0, false, fmt.Errorf("%w: %d", ErrNotPowerOfTwo, n)
	}
	if IsLeaf(a) == false || IsLeaf(b) == false {
		return 0, false, fmt.Errorf("mls/tree: the common ancestor of a leaf and something else is "+
			"asked for with node indices %d and %d, which are not both leaves", a, b)
	}
	if a == b {
		return a, true, nil
	}

	pathA, err := DirectPath(a, n)
	if err != nil {
		return 0, false, err
	}
	pathB, err := DirectPath(b, n)
	if err != nil {
		return 0, false, err
	}

	onPathB := make(map[uint32]bool, len(pathB)+1)
	onPathB[b] = true
	for _, node := range pathB {
		onPathB[node] = true
	}

	// pathA is ordered from the leaf upwards, so the first node found on both paths is the
	// LOWEST one. Scanning from the other end would return the root, which is on every path and
	// therefore says nothing about where the two subtrees meet.
	for _, node := range pathA {
		if onPathB[node] {
			return node, true, nil
		}
	}

	return 0, false, fmt.Errorf("mls/tree: leaves %d and %d in a tree of %d leaves share no node "+
		"above them, which is impossible for two leaves of the same tree", a, b, n)
}

// PathSecretForNewMember returns the path secret a commit must deliver to a new member,
// choosing the one belonging to the lowest common ancestor.
//
// The secrets are those the committer generated for its own update path, keyed by node index.
// The lowest common ancestor is always one of them: it lies on the committer's direct path, and
// an UpdatePath carries a secret for every non-blank node on that path.
//
// It returns false when the ancestor carries no secret, which happens when the ancestor is a
// blank node — the committer's filtered path skips those. A caller must then send no path
// secret at all rather than an empty one: the field is optional, and the two are different on
// the wire.
func PathSecretForNewMember(
	committerLeaf, newMemberLeaf, n uint32,
	secretsByNode map[uint32][]byte,
) (uint32, []byte, bool, error) {
	ancestor, ok, err := LowestCommonAncestor(committerLeaf, newMemberLeaf, n)
	if err != nil {
		return 0, nil, false, err
	}
	if !ok {
		return 0, nil, false, fmt.Errorf("mls/tree: no common ancestor for leaves %d and %d",
			committerLeaf, newMemberLeaf)
	}

	secret, present := secretsByNode[ancestor]
	if !present || len(secret) == 0 {
		return ancestor, nil, false, nil
	}
	return ancestor, secret, true, nil
}
