package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Session serialisation.
//
// # Why this exists
//
// A ratchet session lives in memory, but a chat client does not: the process is killed
// when the user swipes it away, and the OS reclaims it under memory pressure. Without a
// way to persist the ratchet state, every restart would silently start a fresh session,
// which is exactly the situation the double ratchet exists to prevent — the two sides
// would disagree about chain positions and every subsequent message would be
// undecryptable, with no error that explains why.
//
// # The snapshot is key material
//
// A snapshot contains the root key, both chain keys, the local ratchet private key and
// every cached skipped message key. Anyone who can read it can decrypt the session's
// future traffic and much of its past.
//
// It is therefore the CALLER's responsibility to encrypt it. The client stores snapshots
// inside the vault, which is AES-256-GCM under a key derived from the user's passphrase
// and the device's hardware key. Writing a snapshot to plain storage would be a total
// compromise, and the tests here cannot detect that mistake — only the caller can avoid
// it.
//
// # Format
//
// A versioned, length-prefixed binary encoding. Length prefixes are not decoration: a
// variable-length field written without one makes the format ambiguous, and an ambiguous
// format is one where a crafted snapshot can be made to parse as a different session.
const (
	// snapshotVersion 2 added the peer's identity signing key. Version 1 snapshots
	// are rejected rather than migrated: a session with no peer identity could not
	// display a safety number, and quietly restoring one would leave the user with
	// a verification screen that cannot verify anything. Bumping the version is
	// safe here because no released build ever wrote a snapshot.
	snapshotVersion byte = 2

	// SnapshotSizeLimit bounds a decoded snapshot. A real one is a few kilobytes; the
	// ceiling exists so that a malformed length field cannot cause a huge allocation.
	SnapshotSizeLimit = 1 << 20
)

// ErrBadSnapshot means a snapshot could not be decoded.
var ErrBadSnapshot = errors.New("scs1: malformed session snapshot")

// Snapshot encodes the session for storage.
//
// The caller MUST encrypt the result before it touches disk.
func (s *Session) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]byte, 0, 512)
	out = append(out, 'S', 'C', 'S', '1', snapshotVersion)

	out = append(out, s.rootKey[:]...)
	out = append(out, s.sendDir, s.recvDir)

	out = appendBytes(out, s.sessionAD)
	out = appendBytes(out, s.peerSigning)
	out = appendBytes(out, s.dhSelfPub)
	out = appendBytes(out, s.dhRemote)

	// crypto/ecdh does not expose a private key's scalar for reading, but it can
	// produce one: Bytes returns a copy. That copy is key material, so it is zeroed as
	// soon as it has been written.
	if s.dhSelfPriv == nil {
		out = appendBytes(out, nil)
	} else {
		scalar := s.dhSelfPriv.Bytes()
		out = appendBytes(out, scalar)
		Zero(scalar)
	}

	if s.hasRemote {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}

	out = appendBytes(out, s.ckSend)
	out = appendBytes(out, s.ckRecv)

	out = binary.BigEndian.AppendUint32(out, s.ns)
	out = binary.BigEndian.AppendUint32(out, s.nr)
	out = binary.BigEndian.AppendUint32(out, s.pn)
	out = binary.BigEndian.AppendUint64(out, uint64(s.lastRatchet.Unix()))

	// Only keys that are actually cached are written. The order slice may hold stale
	// entries whose key was already consumed, and writing those would put a count in the
	// header that the decoder could not reconcile.
	live := make([]skippedKey, 0, len(s.skippedOrder))
	for _, key := range s.skippedOrder {
		if _, ok := s.skipped[key]; ok {
			live = append(live, key)
		}
	}

	out = binary.BigEndian.AppendUint32(out, uint32(len(live)))
	for _, key := range live {
		mk := s.skipped[key]
		out = append(out, key.ratchet[:]...)
		out = binary.BigEndian.AppendUint32(out, key.counter)
		out = append(out, mk.Key[:]...)
		out = append(out, mk.Nonce[:]...)
	}

	return out, nil
}

// RestoreSession rebuilds a session from a snapshot.
//
// Every field is bounds checked before use. A snapshot is attacker-influenced in the
// sense that a corrupted one must fail cleanly rather than panicking inside a client.
func RestoreSession(blob []byte) (*Session, error) {
	if len(blob) > SnapshotSizeLimit {
		return nil, fmt.Errorf("%w: snapshot exceeds %d bytes", ErrBadSnapshot, SnapshotSizeLimit)
	}
	if len(blob) < 9 {
		return nil, fmt.Errorf("%w: too short", ErrBadSnapshot)
	}
	if string(blob[:4]) != "SCS1" {
		return nil, fmt.Errorf("%w: bad magic", ErrBadSnapshot)
	}
	if blob[4] != snapshotVersion {
		return nil, fmt.Errorf("%w: version %d is not supported", ErrBadSnapshot, blob[4])
	}

	r := &snapshotReader{buf: blob, pos: 5}

	s := &Session{
		skipped: make(map[skippedKey]*MessageKey),
	}

	if err := r.readInto(s.rootKey[:]); err != nil {
		return nil, err
	}

	var err error
	if s.sendDir, err = r.readByte(); err != nil {
		return nil, err
	}
	if s.recvDir, err = r.readByte(); err != nil {
		return nil, err
	}

	if s.sessionAD, err = r.readBytes(); err != nil {
		return nil, err
	}
	if s.peerSigning, err = r.readBytes(); err != nil {
		return nil, err
	}
	if s.dhSelfPub, err = r.readBytes(); err != nil {
		return nil, err
	}
	if s.dhRemote, err = r.readBytes(); err != nil {
		return nil, err
	}

	scalar, err := r.readBytes()
	if err != nil {
		return nil, err
	}
	if len(scalar) > 0 {
		priv, err := X25519FromBytes(scalar)
		Zero(scalar)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadSnapshot, err)
		}
		s.dhSelfPriv = priv
	} else {
		Zero(scalar)
	}

	hasRemote, err := r.readByte()
	if err != nil {
		return nil, err
	}
	s.hasRemote = hasRemote == 1

	if s.ckSend, err = r.readBytes(); err != nil {
		return nil, err
	}
	if s.ckRecv, err = r.readBytes(); err != nil {
		return nil, err
	}

	if s.ns, err = r.readUint32(); err != nil {
		return nil, err
	}
	if s.nr, err = r.readUint32(); err != nil {
		return nil, err
	}
	if s.pn, err = r.readUint32(); err != nil {
		return nil, err
	}
	unix, err := r.readUint64()
	if err != nil {
		return nil, err
	}
	s.lastRatchet = time.Unix(int64(unix), 0)

	count, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	// The cache bound is enforced on decode as well as on use: a snapshot claiming a
	// million skipped keys must be refused before anything is allocated for it.
	if count > MaxSkippedKeys {
		return nil, fmt.Errorf("%w: %d skipped keys exceeds the bound of %d",
			ErrBadSnapshot, count, MaxSkippedKeys)
	}

	for i := uint32(0); i < count; i++ {
		var key skippedKey
		if err := r.readInto(key.ratchet[:]); err != nil {
			return nil, err
		}
		if key.counter, err = r.readUint32(); err != nil {
			return nil, err
		}

		mk := &MessageKey{}
		if err := r.readInto(mk.Key[:]); err != nil {
			return nil, err
		}
		if err := r.readInto(mk.Nonce[:]); err != nil {
			return nil, err
		}
		s.skipped[key] = mk
		s.skippedOrder = append(s.skippedOrder, key)
	}

	if err := s.validateRestored(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// validateRestored rejects a snapshot whose fields are the wrong shape.
//
// A structurally plausible but internally inconsistent session is worse than a rejected
// one: it would fail later, during decryption, where the cause is far harder to see.
func (s *Session) validateRestored() error {
	if len(s.ckSend) != 0 && len(s.ckSend) != ChainKeySize {
		return fmt.Errorf("%w: sending chain is %d bytes", ErrBadSnapshot, len(s.ckSend))
	}
	if len(s.ckRecv) != 0 && len(s.ckRecv) != ChainKeySize {
		return fmt.Errorf("%w: receiving chain is %d bytes", ErrBadSnapshot, len(s.ckRecv))
	}
	if len(s.dhSelfPub) != X25519KeySize {
		return fmt.Errorf("%w: local ratchet public key is %d bytes", ErrBadSnapshot, len(s.dhSelfPub))
	}
	if len(s.peerSigning) != 0 && len(s.peerSigning) != Ed25519PublicKeySize {
		return fmt.Errorf("%w: peer identity key is %d bytes", ErrBadSnapshot, len(s.peerSigning))
	}
	if s.hasRemote && len(s.dhRemote) != X25519KeySize {
		return fmt.Errorf("%w: remote ratchet key is %d bytes", ErrBadSnapshot, len(s.dhRemote))
	}
	if s.sendDir == s.recvDir {
		// The two directions must differ, or the session's anti-reflection property is
		// gone. A snapshot that says otherwise is corrupt.
		return fmt.Errorf("%w: both directions are %#x", ErrBadSnapshot, s.sendDir)
	}
	if s.dhSelfPriv == nil {
		return fmt.Errorf("%w: no local ratchet private key", ErrBadSnapshot)
	}
	return nil
}

// appendBytes writes a 16-bit length prefix followed by the bytes.
func appendBytes(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(field)))
	return append(dst, field...)
}

// snapshotReader is a bounds-checked cursor over a snapshot.
type snapshotReader struct {
	buf []byte
	pos int
}

func (r *snapshotReader) remaining() int { return len(r.buf) - r.pos }

func (r *snapshotReader) readInto(dst []byte) error {
	if r.remaining() < len(dst) {
		return fmt.Errorf("%w: wanted %d bytes, %d remain", ErrBadSnapshot, len(dst), r.remaining())
	}
	copy(dst, r.buf[r.pos:r.pos+len(dst)])
	r.pos += len(dst)
	return nil
}

func (r *snapshotReader) readByte() (byte, error) {
	if r.remaining() < 1 {
		return 0, fmt.Errorf("%w: wanted a byte, none remain", ErrBadSnapshot)
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *snapshotReader) readBytes() ([]byte, error) {
	if r.remaining() < 2 {
		return nil, fmt.Errorf("%w: missing length prefix", ErrBadSnapshot)
	}
	n := int(binary.BigEndian.Uint16(r.buf[r.pos : r.pos+2]))
	r.pos += 2
	if r.remaining() < n {
		return nil, fmt.Errorf("%w: wanted %d bytes, %d remain", ErrBadSnapshot, n, r.remaining())
	}
	out := make([]byte, n)
	copy(out, r.buf[r.pos:r.pos+n])
	r.pos += n
	return out, nil
}

func (r *snapshotReader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("%w: missing uint32", ErrBadSnapshot)
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

func (r *snapshotReader) readUint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("%w: missing uint64", ErrBadSnapshot)
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos : r.pos+8])
	r.pos += 8
	return v, nil
}
