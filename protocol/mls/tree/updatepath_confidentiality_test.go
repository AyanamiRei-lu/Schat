package tree

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/AyanamiRei-lu/Schat/protocol/mls/crypto"
)

// TestUpdatePathCiphertextsRejectEveryoneElse tests the negative side of path secret
// delivery, which is the side that decides whether the construction is confidential at all.
//
// The earlier end-to-end test only showed that the intended recipient CAN open each
// ciphertext. That is necessary and nowhere near sufficient: an implementation that
// encrypted to the wrong key, or that failed to bind the label and context, would still pass
// it. This test asserts the three ways a ciphertext must refuse to open:
//
//  1. With any other member's private key. A path secret handed to a member outside the
//     resolution is a disclosure — the recipient would learn an epoch key it is not entitled
//     to, and nothing else in the protocol would notice.
//  2. With the right key but a DIFFERENT group context. The context is what binds a
//     ciphertext to one group and epoch; without it, a path secret could be replayed from
//     another epoch of the same group.
//  3. With the right key and context but a different label. The label is the domain
//     separator between the several places MLS uses HPKE; losing it would let a ciphertext
//     from one purpose be accepted in another.
//
// Each check counts what it verified, so a test that silently stopped exercising cases would
// report a smaller number rather than passing quietly.

func TestUpdatePathCiphertextsRejectEveryoneElse(t *testing.T) {
	tree, privateKeys := buildTwoLevelTree(t)

	groupContext := []byte("a provisional group context")
	otherContext := []byte("a different group context")

	initial := make([]byte, suiteUnderTest.HashSize())
	if _, err := rand.Read(initial); err != nil {
		t.Fatal(err)
	}

	result, err := GenerateUpdatePath(tree, 0, groupContext, initial, nil, suiteUnderTest)
	if err != nil {
		t.Fatalf("GenerateUpdatePath: %v", err)
	}

	wrongKeyChecks, wrongContextChecks, wrongLabelChecks := 0, 0, 0
	intendedChecks := 0

	for i := range result.FilteredPath {
		node := result.Path.Nodes[i]

		below := uint32(0)
		if i > 0 {
			below = result.FilteredPath[i-1]
		}
		copath, ok := Sibling(below, 4)
		if !ok {
			t.Fatalf("node %d has no sibling", below)
		}
		resolution, err := Resolution(tree, copath)
		if err != nil {
			t.Fatalf("Resolution(%d): %v", copath, err)
		}

		for j, member := range resolution {
			ct := node.EncryptedPathSecret[j]

			// The intended recipient must succeed; without this the negatives below could
			// all pass on a ciphertext that opens for nobody.
			recovered, err := crypto.DecryptWithLabel(privateKeys[member], "UpdatePathNode",
				groupContext, ct.KemOutput, ct.Ciphertext, suiteUnderTest)
			if err != nil {
				t.Fatalf("the intended recipient (node %d) could not open its own ciphertext: %v", member, err)
			}
			if !bytes.Equal(recovered, result.PathSecrets[i]) {
				t.Fatalf("node %d recovered the wrong secret", member)
			}
			intendedChecks++

			// 1. Every other key in the tree must fail. Every node is tried, including ones
			//    that are not in any resolution and including other path nodes, because the
			//    interesting failure is a key that is "close" — a sibling, or the node above.
			for other, priv := range privateKeys {
				if other == member {
					continue
				}
				if opened, err := crypto.DecryptWithLabel(priv, "UpdatePathNode", groupContext,
					ct.KemOutput, ct.Ciphertext, suiteUnderTest); err == nil {
					t.Fatalf("node %d opened a ciphertext addressed to node %d and recovered %x — "+
						"a path secret reachable by a member outside the resolution is a disclosure",
						other, member, opened)
				}
				wrongKeyChecks++
			}

			// 2. The right key under a different context must fail.
			if opened, err := crypto.DecryptWithLabel(privateKeys[member], "UpdatePathNode",
				otherContext, ct.KemOutput, ct.Ciphertext, suiteUnderTest); err == nil {
				t.Fatalf("node %d opened its ciphertext under a different group context and "+
					"recovered %x — the context is not bound, so a path secret could be replayed",
					member, opened)
			}
			wrongContextChecks++

			// 3. The right key and context under a different label must fail.
			if opened, err := crypto.DecryptWithLabel(privateKeys[member], "UpdatePathNodeX",
				groupContext, ct.KemOutput, ct.Ciphertext, suiteUnderTest); err == nil {
				t.Fatalf("node %d opened its ciphertext under a different label and recovered %x — "+
					"the label is not a domain separator here", member, opened)
			}
			wrongLabelChecks++
		}
	}

	if intendedChecks == 0 {
		t.Fatal("no ciphertext was exercised, so the negatives above proved nothing")
	}

	t.Logf("path secret delivery: %d ciphertexts opened by their intended recipient; "+
		"%d attempts with other members' keys, %d with a different group context and %d with a "+
		"different label all refused",
		intendedChecks, wrongKeyChecks, wrongContextChecks, wrongLabelChecks)
}
