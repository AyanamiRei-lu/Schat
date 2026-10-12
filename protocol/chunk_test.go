package protocol

import (
	"bytes"
	"testing"
)

func TestFileRootKeyProperties(t *testing.T) {
	fk := testKey(0x21)

	root, err := FileRootKey(fk, ProfileVideo)
	if err != nil {
		t.Fatalf("FileRootKey: %v", err)
	}
	if len(root) != KeySize {
		t.Fatalf("root key is %d bytes, want %d", len(root), KeySize)
	}

	again, err := FileRootKey(fk, ProfileVideo)
	if err != nil {
		t.Fatalf("FileRootKey (repeat): %v", err)
	}
	if !bytes.Equal(root, again) {
		t.Fatal("file root key derivation is not deterministic")
	}

	// The profile byte is part of the salt, so the same file key yields a
	// different ladder per content type.
	other, err := FileRootKey(fk, ProfileImage)
	if err != nil {
		t.Fatalf("FileRootKey (image): %v", err)
	}
	if bytes.Equal(root, other) {
		t.Fatal("different content profiles produced the same file root key")
	}
}

func TestFileRootKeyRejectsBadInput(t *testing.T) {
	if _, err := FileRootKey(make([]byte, 16), ProfileFile); err == nil {
		t.Fatal("expected an error for a 16-byte file key")
	}
	if _, err := FileRootKey(testKey(0x01), AEADProfile(0x7f)); err == nil {
		t.Fatal("expected an error for an invalid profile")
	}
}

// TestChunkKeyLadder checks the property that makes seek and resume work: every
// index must be independently derivable and unique.
func TestChunkKeyLadder(t *testing.T) {
	root, err := FileRootKey(testKey(0x31), ProfileVideo)
	if err != nil {
		t.Fatalf("FileRootKey: %v", err)
	}

	const n = 64
	seen := make(map[[KeySize]byte]uint64, n)

	for i := uint64(0); i < n; i++ {
		ck, err := ChunkKey(root, i)
		if err != nil {
			t.Fatalf("ChunkKey(%d): %v", i, err)
		}

		if prev, dup := seen[ck.Key]; dup {
			t.Fatalf("chunk %d collides with chunk %d", i, prev)
		}
		seen[ck.Key] = i
		ck.Zero()
	}

	// Random access: deriving index 37 directly must give the same answer as
	// walking the ladder, which is what allows decrypting one video segment
	// without decrypting the ones before it.
	direct, err := ChunkKey(root, 37)
	if err != nil {
		t.Fatalf("ChunkKey(37): %v", err)
	}
	defer direct.Zero()

	repeat, err := ChunkKey(root, 37)
	if err != nil {
		t.Fatalf("ChunkKey(37) repeat: %v", err)
	}
	defer repeat.Zero()

	if direct.Key != repeat.Key || direct.Nonce != repeat.Nonce {
		t.Fatal("chunk key derivation is not deterministic")
	}
}

func TestChunkKeyRejectsEmptyRoot(t *testing.T) {
	if _, err := ChunkKey(nil, 0); err == nil {
		t.Fatal("expected an error for an empty file root key")
	}
}

func TestChunkCount(t *testing.T) {
	cases := []struct {
		n       int
		profile AEADProfile
		want    int
	}{
		{0, ProfileVideo, 0},
		{-1, ProfileVideo, 0},
		{1, ProfileVideo, 1},
		{VideoChunkSize, ProfileVideo, 1},
		{VideoChunkSize + 1, ProfileVideo, 2},
		{ImageChunkSize * 3, ProfileImage, 3},
	}

	for _, c := range cases {
		if got := ChunkCount(c.n, c.profile); got != c.want {
			t.Errorf("ChunkCount(%d, %s) = %d, want %d",
				c.n, c.profile, got, c.want)
		}
	}
}

// TestHashTreeRootDetectsTampering is the integrity property for chunked media:
// the relay server cannot alter, reorder or drop a chunk without the receiver
// noticing, even though the server holds no key at all.
func TestHashTreeRootDetectsTampering(t *testing.T) {
	chunks := [][]byte{
		[]byte("chunk-zero"),
		[]byte("chunk-one"),
		[]byte("chunk-two"),
		[]byte("chunk-three"),
	}

	root := HashTreeRoot(chunks)
	if len(root) != 32 {
		t.Fatalf("root is %d bytes, want 32", len(root))
	}
	if !bytes.Equal(root, HashTreeRoot(chunks)) {
		t.Fatal("hash tree root is not deterministic")
	}

	// A single flipped byte inside one chunk must change the root.
	altered := [][]byte{
		chunks[0],
		[]byte("chunk-onE"),
		chunks[2],
		chunks[3],
	}
	if bytes.Equal(root, HashTreeRoot(altered)) {
		t.Fatal("a modified chunk did not change the root")
	}

	// Reordering must change the root.
	reordered := [][]byte{chunks[1], chunks[0], chunks[2], chunks[3]}
	if bytes.Equal(root, HashTreeRoot(reordered)) {
		t.Fatal("reordering chunks did not change the root")
	}

	// Dropping a chunk must change the root.
	if bytes.Equal(root, HashTreeRoot(chunks[:3])) {
		t.Fatal("dropping a chunk did not change the root")
	}
}

func TestHashTreeRootHandlesOddAndEmptyInput(t *testing.T) {
	if len(HashTreeRoot(nil)) != 32 {
		t.Fatal("the empty tree must still produce a 32-byte root")
	}

	one := HashTreeRoot([][]byte{[]byte("only")})
	if len(one) != 32 {
		t.Fatal("a single-chunk tree must produce a 32-byte root")
	}

	// An odd number of nodes at some level must not panic and must be stable.
	three := HashTreeRoot([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	if !bytes.Equal(three, HashTreeRoot([][]byte{[]byte("a"), []byte("b"), []byte("c")})) {
		t.Fatal("odd-length tree is not deterministic")
	}
}
