package protocol

import (
	"bytes"
	"testing"
)

// TestGroupEpochKeyBindsGroupID checks the bridge from MLS to the content
// layer: two groups that somehow reached the same exporter secret must still
// produce unrelated content keys.
func TestGroupEpochKeyBindsGroupID(t *testing.T) {
	exporter := bytes.Repeat([]byte{0x61}, 32)

	a, err := GroupEpochKey(exporter, []byte("group-alpha"))
	if err != nil {
		t.Fatalf("GroupEpochKey: %v", err)
	}
	if len(a) != KeySize {
		t.Fatalf("epoch key is %d bytes, want %d", len(a), KeySize)
	}

	again, err := GroupEpochKey(exporter, []byte("group-alpha"))
	if err != nil {
		t.Fatalf("GroupEpochKey (repeat): %v", err)
	}
	if !bytes.Equal(a, again) {
		t.Fatal("group epoch key derivation is not deterministic")
	}

	b, err := GroupEpochKey(exporter, []byte("group-beta"))
	if err != nil {
		t.Fatalf("GroupEpochKey (other group): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("the group identifier did not affect the epoch key")
	}

	if _, err := GroupEpochKey(nil, []byte("group")); err == nil {
		t.Fatal("expected an error for an empty exporter secret")
	}
}

// TestSenderChainKeySeparation ensures no two members of a group can share a
// sending chain, which would let one member forge another's messages.
func TestSenderChainKeySeparation(t *testing.T) {
	epochKey := testKey(0x71)

	seen := make(map[string]uint32)
	for leaf := uint32(0); leaf < 32; leaf++ {
		sk, err := SenderChainKey(epochKey, leaf)
		if err != nil {
			t.Fatalf("SenderChainKey(%d): %v", leaf, err)
		}
		if len(sk) != KeySize {
			t.Fatalf("sender chain key is %d bytes, want %d", len(sk), KeySize)
		}
		if prev, dup := seen[string(sk)]; dup {
			t.Fatalf("leaf %d shares a sending chain with leaf %d", leaf, prev)
		}
		seen[string(sk)] = leaf
	}

	if _, err := SenderChainKey(make([]byte, 16), 0); err == nil {
		t.Fatal("expected an error for a short epoch key")
	}
}

// TestGroupEpochKeyIsIndependentOfPairwiseKeys confirms the MLS-derived group
// key cannot coincide with a 1:1 message key derived from the same-looking
// input, because the labels differ.
func TestGroupEpochKeyIsIndependentOfPairwiseKeys(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x81}, 32)

	groupKey, err := GroupEpochKey(ikm, []byte("ctx"))
	if err != nil {
		t.Fatalf("GroupEpochKey: %v", err)
	}

	// The same input under the message label must differ, or a group key could
	// be replayed as a pairwise message key.
	msgKey, err := DeriveLabeled(ikm, LabelMsg, []byte("ctx"), KeySize)
	if err != nil {
		t.Fatalf("DeriveLabeled: %v", err)
	}

	if bytes.Equal(groupKey, msgKey) {
		t.Fatal("group and message derivations agree; domain separation is broken")
	}
}
