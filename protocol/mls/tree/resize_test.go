package tree

import "testing"

// Extending and truncating, checked at several sizes.
//
// These operations decide the tree hash, which is an input to the key schedule, so an
// implementation that disagrees with another about when to truncate computes different epoch
// secrets from identical membership. The checks below are about the SHAPE, because the shape
// is what the two implementations would disagree about.

func twoLeafTreeWithBlankRight(t *testing.T) Tree {
	t.Helper()
	_, aPub := hpkeKey(t, "resize-a")
	_, rootPub := hpkeKey(t, "resize-root")

	return Tree{
		leafNode(aPub),
		{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: rootPub}},
		nil, // the right leaf is blank: the member there was removed
	}
}

func TestTruncateDropsABlankRightSubtree(t *testing.T) {
	ratchet := twoLeafTreeWithBlankRight(t)

	blank, err := RightSubtreeIsBlank(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if !blank {
		t.Fatal("a tree whose entire right subtree is blank was not reported as truncatable")
	}

	truncated, err := Truncate(ratchet)
	if err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	// A two-leaf tree becomes a one-leaf tree: one node, which is both the leaf and the root.
	if len(truncated) != 1 {
		t.Fatalf("truncating a 3-node tree gave %d nodes, want 1", len(truncated))
	}
	if truncated[0] == nil {
		t.Fatal("truncation discarded the live member's leaf")
	}
	if truncated[0].Leaf == nil {
		t.Fatal("the surviving node is not a leaf")
	}

	// The result must itself be a valid layout, or every later operation on it is nonsense.
	leaves, err := LeavesForLayout(uint32(len(truncated)))
	if err != nil {
		t.Fatalf("the truncated tree is not a valid layout: %v", err)
	}
	if leaves != 1 {
		t.Fatalf("the truncated tree has %d leaves, want 1", leaves)
	}
}

func TestTruncateRefusesToDiscardALiveMember(t *testing.T) {
	_, aPub := hpkeKey(t, "resize-a")
	_, bPub := hpkeKey(t, "resize-b")
	_, rootPub := hpkeKey(t, "resize-root")

	live := Tree{
		leafNode(aPub),
		{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: rootPub}},
		leafNode(bPub),
	}

	blank, err := RightSubtreeIsBlank(live)
	if err != nil {
		t.Fatal(err)
	}
	if blank {
		t.Fatal("a tree with a live member in its right subtree was reported as blank")
	}
	if _, err := Truncate(live); err == nil {
		t.Fatal("truncating a tree with a live member in the right subtree was allowed, which " +
			"would remove that member with no proposal saying so")
	}

	// A one-leaf tree has no right subtree, and truncating it would leave nothing.
	single := Tree{leafNode(aPub)}
	if _, err := Truncate(single); err == nil {
		t.Fatal("a one-leaf tree was truncated")
	}
}

func TestTruncateAtAFourLeafSize(t *testing.T) {
	// Four leaves: nodes 0..6, root at 3, right subtree rooted at 5 spanning nodes 4..6.
	_, pub := hpkeKey(t, "resize-leaf")
	_, rootPub := hpkeKey(t, "resize-root")
	_, subPub := hpkeKey(t, "resize-sub")

	ratchet := make(Tree, 7)
	ratchet[0] = leafNode(pub)
	ratchet[2] = leafNode(pub)
	ratchet[1] = &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: subPub}}
	ratchet[3] = &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: rootPub}}
	// Nodes 4, 5 and 6 stay blank: the right half has no live member.

	truncated, err := Truncate(ratchet)
	if err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if len(truncated) != 3 {
		t.Fatalf("truncating a 7-node tree gave %d nodes, want 3", len(truncated))
	}
	if truncated[0] == nil || truncated[2] == nil || truncated[1] == nil {
		t.Fatal("truncation lost a node of the surviving half")
	}
}

func TestExtendDoublesTheTreeAndKeepsIndices(t *testing.T) {
	single := Tree{leafNode(mustPub(t, "extend-a"))}

	extended, err := Extend(single)
	if err != nil {
		t.Fatalf("Extend: %v", err)
	}
	if len(extended) != 3 {
		t.Fatalf("extending a 1-node tree gave %d nodes, want 3", len(extended))
	}
	// The old tree becomes the left half, so every index below the new root keeps its meaning.
	if extended[0] == nil || extended[0].Leaf == nil {
		t.Fatal("the existing leaf did not stay at index 0")
	}
	if extended[1] != nil || extended[2] != nil {
		t.Fatal("the new level was not left blank")
	}

	// And again: three nodes become seven.
	bigger, err := Extend(extended)
	if err != nil {
		t.Fatal(err)
	}
	if len(bigger) != 7 {
		t.Fatalf("extending a 3-node tree gave %d nodes, want 7", len(bigger))
	}
	if bigger[0] == nil {
		t.Fatal("extending twice lost the original leaf")
	}

	// Extending and truncating a tree with a blank right half returns the original shape,
	// which is the property that makes the two operations inverses rather than merely
	// plausible.
	back, err := Truncate(bigger)
	if err != nil {
		t.Fatalf("truncating the result of an extension failed: %v", err)
	}
	if len(back) != 3 {
		t.Fatalf("extend-then-truncate gave %d nodes, want 3", len(back))
	}
}

func TestNeedsExtensionAndFirstFreeLeaf(t *testing.T) {
	full := Tree{leafNode(mustPub(t, "full-a")), nil, leafNode(mustPub(t, "full-b"))}
	full[1] = &Node{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: mustPub(t, "full-root")}}

	needs, err := NeedsExtension(full)
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Fatal("a tree with no blank leaf slot was not reported as full")
	}
	if _, ok, err := FirstFreeLeaf(full); err != nil || ok {
		t.Fatal("a full tree offered a free leaf slot")
	}

	// A tree with a hole has room, and the new member goes at the RIGHT EDGE — the rightmost
	// blank slot, not the leftmost. The leftmost would put the new member where another
	// member's path already reaches, and the two would disagree about the resulting tree.
	holed := Tree{
		leafNode(mustPub(t, "holed-a")),
		{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: mustPub(t, "holed-root")}},
		nil,
	}
	needs, err = NeedsExtension(holed)
	if err != nil {
		t.Fatal(err)
	}
	if needs {
		t.Fatal("a tree with a blank leaf slot was reported as full")
	}

	leaf, ok, err := FirstFreeLeaf(holed)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("a tree with a blank leaf slot offered none")
	}
	if leaf != 1 {
		t.Fatalf("the free slot is leaf %d, want leaf 1", leaf)
	}

	// With both slots blank it must still choose the rightmost.
	bothBlank := Tree{
		nil,
		{Type: NodeTypeParent, Parent: &ParentNode{EncryptionKey: mustPub(t, "blank-root")}},
		nil,
	}
	leaf, ok, err = FirstFreeLeaf(bothBlank)
	if err != nil || !ok {
		t.Fatalf("FirstFreeLeaf: %v, ok=%v", err, ok)
	}
	if leaf != 1 {
		t.Fatalf("the rightmost free slot is leaf %d, want leaf 1", leaf)
	}
}

func TestResizeRefusesAnInvalidLayout(t *testing.T) {
	// Two nodes is not 2n-1 for any n.
	bad := Tree{leafNode(mustPub(t, "bad"))}
	if _, err := Extend(append(bad, nil)); err == nil {
		t.Fatal("a two-node tree was extended")
	}
	if _, err := Truncate(bad); err == nil {
		t.Fatal("a one-node tree was truncated")
	}
}

func mustPub(t *testing.T, label string) []byte {
	t.Helper()
	_, pub := hpkeKey(t, label)
	return pub
}
