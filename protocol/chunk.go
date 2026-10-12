package protocol

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Chunked media encryption — the chunk key ladder (SCHAT.md section 5.3).
//
// Large media is never loaded into memory as a whole. Instead:
//
//	FK       <- 32 random bytes, unique per file
//	K_root    = HKDF(FK, salt = LabelFile || profile, info = LabelFile, len = 32)
//	CK_i      = HKDF(K_root, salt = LE64(i), info = LabelChunk, len = 44)
//
// Deriving chunk keys from a ladder instead of storing one random key per chunk
// has three concrete benefits:
//
//   - key material is O(1) instead of O(chunks); a 1 GB video has ~1024 chunks,
//     which would otherwise cost tens of kilobytes of resident key material;
//   - any chunk can be decrypted on its own, which is what makes seek, resume
//     and progressive image display possible;
//   - the chunk index is part of the derivation, so chunks cannot be
//     reordered, duplicated or swapped between files.
//
// A file key FK is used for exactly one file, ever. Reusing it would repeat the
// ladder and therefore repeat nonces.
const (
	// ImageChunkSize is the tile size for progressive image decryption.
	ImageChunkSize = 256 * 1024

	// VideoChunkSize is the segment size for seekable video playback.
	VideoChunkSize = 1 << 20 // 1 MiB

	// FileChunkSize is the streaming size for generic file transfer.
	FileChunkSize = 1 << 20 // 1 MiB

	// VoiceFrameSize is the nominal size of one Opus voice frame payload.
	VoiceFrameSize = 200 * 8 // 200 ms at a conservative bitrate

	// DBPageSize is the encrypted database page size.
	DBPageSize = 4096
)

// FileRootKey derives the per-file root key from the file key delivered inside
// an end-to-end encrypted session:
//
//	K_root = HKDF(FK, salt = LabelFile || profile, info = LabelFile, len = 32)
//
// The profile byte is part of the salt, so the same file key would produce
// different ladders for different content types. That is defence in depth: even
// if a file key were somehow reused across types, the ladders stay separate.
//
// Callers MUST NOT reuse FK for a second file.
func FileRootKey(fileKey []byte, profile AEADProfile) ([]byte, error) {
	if len(fileKey) != KeySize {
		return nil, fmt.Errorf("%w: file key must be %d bytes, got %d",
			ErrBadKeySize, KeySize, len(fileKey))
	}
	if !profile.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownProfile, uint8(profile))
	}

	salt := make([]byte, 0, len(LabelFile)+1)
	salt = append(salt, LabelFile...)
	salt = append(salt, byte(profile))

	return HKDF(fileKey, salt, LabelFile, KeySize)
}

// ChunkKey derives the key and nonce for chunk index i:
//
//	CK_i = HKDF(K_root, salt = LE64(i), info = LabelChunk, len = 44)
//
// The returned MessageKey must be zeroed after use.
func ChunkKey(rootKey []byte, index uint64) (*MessageKey, error) {
	if len(rootKey) == 0 {
		return nil, fmt.Errorf("%w: empty file root key", ErrBadKeySize)
	}
	var salt [8]byte
	binary.LittleEndian.PutUint64(salt[:], index)

	raw, err := HKDF(rootKey, salt[:], LabelChunk, MsgKeySize)
	if err != nil {
		return nil, err
	}
	defer Zero(raw)

	mk := &MessageKey{}
	copy(mk.Key[:], raw[:KeySize])
	copy(mk.Nonce[:], raw[KeySize:MsgKeySize])
	return mk, nil
}

// ChunkCount returns how many chunks a payload of n bytes occupies under the
// given profile's chunk size.
func ChunkCount(n int, profile AEADProfile) int {
	if n <= 0 {
		return 0
	}
	size := ChunkSizeFor(profile)
	return (n + size - 1) / size
}

// ChunkSizeFor returns the chunk size used by a content profile.
func ChunkSizeFor(profile AEADProfile) int {
	switch profile {
	case ProfileImage:
		return ImageChunkSize
	case ProfileVideo:
		return VideoChunkSize
	case ProfileVoice:
		return VoiceFrameSize
	case ProfileDatabase:
		return DBPageSize
	default:
		return FileChunkSize
	}
}

// HashTreeRoot computes the Merkle-style integrity root over chunk ciphertexts
// (SCHAT.md section 5.3).
//
// The root is stored inside the encrypted file header. A downloader verifies
// each chunk as it arrives and checks its path to this root, so an attacker who
// controls the relay cannot alter, reorder, duplicate or drop a chunk without
// detection — even though the server itself never sees a key.
//
// Odd nodes at each level are carried up unchanged (the same convention as
// RFC 6962), which makes the tree deterministic for any input length.
func HashTreeRoot(chunks [][]byte) []byte {
	if len(chunks) == 0 {
		empty, _ := blake2b.New256(nil)
		return empty.Sum(nil)
	}

	level := make([][]byte, 0, len(chunks))
	for _, c := range chunks {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic("scs1: blake2b.New256(nil) failed: " + err.Error())
		}
		h.Write(c)
		level = append(level, h.Sum(nil))
	}

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			h, err := blake2b.New256(nil)
			if err != nil {
				panic("scs1: blake2b.New256(nil) failed: " + err.Error())
			}
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}
