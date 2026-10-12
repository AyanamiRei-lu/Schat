// Package protocol implements SCS-1, the SChat Secure Protocol.
//
// SCS-1 is the cryptographic core shared by the SCHAT Android client and, for
// envelope structure handling, the SCHAT relay server. The complete
// specification lives in SCHAT.md sections 4 and 5.
//
// # Design position
//
// SCS-1 deliberately does NOT invent cryptographic primitives. Every primitive
// it uses is a published, long-analysed standard:
//
//	X25519        crypto/ecdh              key agreement
//	Ed25519       crypto/ed25519           signatures and identity
//	HKDF-SHA256   crypto/hkdf (RFC 5869)   key derivation
//	ChaCha20-Poly1305 / XChaCha20-Poly1305 (RFC 8439)   authenticated encryption
//	AES-256-GCM   crypto/cipher            authenticated encryption (HW accelerated)
//	Argon2id      golang.org/x/crypto/argon2 (RFC 9106) password hashing
//	BLAKE2b-256   golang.org/x/crypto/blake2b           hashing, safety numbers
//
// What IS original is the composition layer: the key schedule, the ratchet
// policy, the chunk key ladder, the per-file-format AEAD matrix and the
// metadata protection scheme. This follows Kerckhoffs's principle — security
// must rest on the secrecy of the key, never on the secrecy of the algorithm.
// See SCHAT.md section 11.1 for the full, honest statement.
//
// # Implementation status
//
// This package is being built incrementally. The foundation layer (domain
// separation labels, key derivation, the AEAD profile matrix, length padding
// and memory zeroization) is implemented and covered by tests. The session
// establishment, ratchet, chunking, vault and token layers are stubs whose
// signatures are frozen so that server and client code can be written against
// a stable API; they are implemented in step 2 of the roadmap.
//
// # Constant-time and hygiene rules
//
// Every implementation in this package MUST follow these rules. They are
// security requirements, not style preferences:
//
//   - Compare authentication tags and MACs with crypto/subtle only. Never "==".
//   - Never index a table with secret data.
//   - Zero key material with Zero() as soon as it is no longer needed.
//   - Never log keys, plaintext or nonces.
//   - Use crypto/rand exclusively. math/rand is forbidden.
//   - Never downgrade on a version or parameter mismatch: fail closed.
package protocol
