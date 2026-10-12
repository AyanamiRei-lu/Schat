package protocol

import (
	"crypto/ecdh"
	"fmt"
	"time"
)

// Symmetric and DH ratchet — SCS-DR (SCHAT.md section 4.5).
//
// # Ratchet policy, and a design that had to be abandoned
//
// The DH ratchet fires on exactly one condition: the peer sent a new ratchet
// public key. That is the standard Double Ratchet rule, and it is forced by the
// mathematics rather than chosen for simplicity.
//
// SCHAT.md section 4.5 originally specified an additional "adaptive threshold":
// refresh the sending chain after T messages, where T was derived from the root
// key so both sides agreed on it without communicating. It reads like a free
// optimisation — one DH operation per T messages instead of one per round trip.
// It is not implementable, and this implementation is what proved it.
//
// The reason is that ratchet keys must advance in strict alternation. The receiver
// derives the shared secret as DH(its_current_ratchet_private, incoming_ratchet_pub).
// If the sender refreshes its key while still holding a stale remote key, the
// receiver has already moved on to a newer private key and computes a different
// secret. The session does not degrade — it breaks outright, and only in bursts,
// which is the worst possible failure mode to debug.
//
// A concrete trace: A sends a burst, B replies once (B now holds ratchet key
// R_B2), then A refreshes a second time using the stale R_B1 it last saw. B
// computes DH(R_B2, R_A_new) while A computed DH(R_A_new, R_B1). Different
// secrets, dead session.
//
// The optimisation was also never needed. In the standard Double Ratchet each side
// performs one DH operation per round trip, which is already the minimum for
// post-compromise security and is naturally rate-limited by the conversation
// itself. Removing it cost nothing, so it is gone rather than approximated.
//
// Post-compromise security is therefore achieved at conversational cadence: every
// time the peer replies, both chains advance. A purely one-way burst does not
// refresh entropy, which is correct and unavoidable — security cannot be
// manufactured out of traffic that never arrives.
//
// # Two failure modes that shaped the implementation
//
// Both were found while writing the test suite, and both are the kind of thing
// that only shows up once a ratchet actually runs.
//
//  1. A LATE MESSAGE FROM AN OLD CHAIN LOOKS LIKE A NEW RATCHET. The obvious
//     implementation checks "has the peer's ratchet key changed?" first. A message
//     that was delayed past the peer's next ratchet step carries the OLD key, so
//     that check fires, a bogus receiving chain is installed, and the session is
//     destroyed. DecryptMessage therefore consults the skipped-key cache BEFORE
//     deciding to ratchet.
//
//  2. AN UNAUTHENTICATED FRAME MUST NOT BE ABLE TO DESTROY A SESSION. Header
//     bytes are only authenticated once the AEAD tag verifies, so an attacker can
//     inject any ratchet key they like. If the ratchet were committed before
//     authentication, one forged packet would permanently desynchronise the
//     conversation — a cheap and total denial of service. The ratchet state is
//     therefore snapshotted and rolled back when authentication fails, and the
//     symmetric chain is advanced only AFTER a frame authenticates.
const (
	// MaxSkippedKeys bounds the out-of-order message key cache. Exceeding it
	// rejects the message instead of growing memory, so a forged counter cannot be
	// used as a denial-of-service lever (SCHAT.md section 4.5).
	MaxSkippedKeys = 2000

	// MaxReceiveGap bounds how far ahead of the expected counter a single message
	// may claim to be. A larger gap could never be cached anyway, so rejecting
	// early avoids doing the work first.
	MaxReceiveGap = MaxSkippedKeys
)

// ratchetState is a snapshot of everything a DH ratchet mutates.
//
// It exists purely so that a frame which fails authentication can leave no trace.
type ratchetState struct {
	rootKey     RootKey
	ckSend      []byte
	ckRecv      []byte
	dhSelfPriv  *ecdh.PrivateKey
	dhSelfPub   []byte
	dhRemote    []byte
	hasRemote   bool
	ns          uint32
	nr          uint32
	pn          uint32
	lastRatchet time.Time
}

// captureState copies the mutable ratchet state.
//
// The ratchet private key is copied by reference: crypto/ecdh private keys are
// immutable once created, and there is no way to duplicate or zero one anyway.
func (s *Session) captureState() ratchetState {
	return ratchetState{
		rootKey:     s.rootKey,
		ckSend:      append([]byte(nil), s.ckSend...),
		ckRecv:      append([]byte(nil), s.ckRecv...),
		dhSelfPriv:  s.dhSelfPriv,
		dhSelfPub:   append([]byte(nil), s.dhSelfPub...),
		dhRemote:    append([]byte(nil), s.dhRemote...),
		hasRemote:   s.hasRemote,
		ns:          s.ns,
		nr:          s.nr,
		pn:          s.pn,
		lastRatchet: s.lastRatchet,
	}
}

// restoreState puts back a snapshot taken by captureState.
func (s *Session) restoreState(st ratchetState) {
	s.rootKey = st.rootKey
	s.ckSend = st.ckSend
	s.ckRecv = st.ckRecv
	s.dhSelfPriv = st.dhSelfPriv
	s.dhSelfPub = st.dhSelfPub
	s.dhRemote = st.dhRemote
	s.hasRemote = st.hasRemote
	s.ns = st.ns
	s.nr = st.nr
	s.pn = st.pn
	s.lastRatchet = st.lastRatchet
}

// EncryptMessage advances the sending chain and encrypts plaintext.
//
// The plaintext is padded to a length bucket before encryption, so the ciphertext
// length reveals only the bucket rather than the exact message size.
func (s *Session) EncryptMessage(plaintext []byte, profile AEADProfile) (*Envelope, error) {
	if !profile.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownProfile, uint8(profile))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dhSelfPriv == nil || len(s.ckSend) == 0 {
		return nil, fmt.Errorf("scs1: session is not initialised for sending")
	}

	mk, err := DeriveMessageKey(s.ckSend, s.sendDir, uint64(s.ns))
	if err != nil {
		return nil, err
	}
	defer mk.Zero()

	hdr := Header{
		Version:      WireVersion,
		Profile:      profile,
		PrevChainLen: s.pn,
		Counter:      s.ns,
	}
	copy(hdr.RatchetPub[:], s.dhSelfPub)

	padded := Pad(plaintext)
	defer Zero(padded)

	ct, err := profile.Seal(mk.Key[:], mk.NonceFor(profile), padded, AssociatedData(s.sessionAD, hdr))
	if err != nil {
		return nil, err
	}

	// Advance only after a successful seal. A failed encryption must not consume a
	// counter, or the peer would be permanently one key behind.
	next, err := AdvanceChain(s.ckSend)
	if err != nil {
		return nil, err
	}
	Zero(s.ckSend)
	s.ckSend = next
	s.ns++

	return &Envelope{Header: hdr, Ciphertext: ct}, nil
}

// DecryptMessage consumes an envelope and returns its plaintext.
//
// It is safe against replay, reordering and tampering, and it fails closed: any
// problem returns an error and no plaintext. A frame that fails authentication
// leaves the session state exactly as it was.
func (s *Session) DecryptMessage(env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("scs1: nil envelope")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hdr := env.Header
	if hdr.Version != WireVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, hdr.Version)
	}
	if !hdr.Profile.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownProfile, uint8(hdr.Profile))
	}
	if len(env.Ciphertext) < hdr.Profile.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext shorter than the authentication tag", ErrShortBuffer)
	}

	// Step 1: a message we already skipped past.
	//
	// This MUST come before the ratchet decision below. A message delayed past the
	// peer's next ratchet step carries the previous ratchet key, which looks
	// exactly like a new ratchet key from the other direction; treating it as one
	// installs a bogus receiving chain and destroys the session.
	if mk := s.takeSkippedLocked(hdr.RatchetPub[:], hdr.Counter); mk != nil {
		defer mk.Zero()
		return s.openLocked(hdr.Profile, mk, hdr, env.Ciphertext)
	}

	if len(s.ckRecv) == 0 && s.hasRemote && EqualBytes(s.dhRemote, hdr.RatchetPub[:]) {
		// We know this ratchet key but have no receiving chain for it, which means
		// the session was never initialised for receiving.
		return nil, fmt.Errorf("scs1: session is not initialised for receiving")
	}

	// Everything from here on mutates ratchet state, so take a snapshot that can
	// be rolled back if the frame turns out to be forged.
	snapshot := s.captureState()
	rollback := func() { s.restoreState(snapshot) }

	// Step 2: a new ratchet key means the peer has ratcheted. The tail of the
	// previous receiving chain must be derived and cached FIRST, or messages still
	// in flight on that chain become permanently undecryptable.
	if !s.hasRemote || !EqualBytes(s.dhRemote, hdr.RatchetPub[:]) {
		if err := s.skipMessageKeysLocked(hdr.PrevChainLen); err != nil {
			rollback()
			return nil, err
		}
		if err := s.dhRatchetReceivingLocked(hdr.RatchetPub[:]); err != nil {
			rollback()
			return nil, err
		}
	}

	if len(s.ckRecv) == 0 {
		rollback()
		return nil, fmt.Errorf("scs1: no receiving chain is available")
	}

	// Step 3: reject anything at or below the expected counter. Such a frame has
	// either been delivered in order already, or its key was cached and consumed in
	// step 1 — either way, seeing it again is a replay.
	if hdr.Counter < s.nr {
		rollback()
		return nil, fmt.Errorf("%w: counter %d is below the expected %d",
			ErrReplay, hdr.Counter, s.nr)
	}

	// Step 4: derive and cache the keys of any messages the peer sent but that have
	// not arrived yet.
	if hdr.Counter > s.nr {
		gap := uint64(hdr.Counter) - uint64(s.nr)
		if gap > MaxReceiveGap {
			rollback()
			return nil, fmt.Errorf("%w: gap %d exceeds %d", ErrTooManySkipped, gap, MaxReceiveGap)
		}
		if err := s.skipMessageKeysLocked(hdr.Counter); err != nil {
			rollback()
			return nil, err
		}
	}

	mk, err := DeriveMessageKey(s.ckRecv, s.recvDir, uint64(hdr.Counter))
	if err != nil {
		rollback()
		return nil, err
	}
	defer mk.Zero()

	plaintext, err := s.openLocked(hdr.Profile, mk, hdr, env.Ciphertext)
	if err != nil {
		// Authentication failed. The frame may have been forged with a fake ratchet
		// key, a fake counter or a fake profile, so nothing it caused may persist.
		//
		// Skipped keys derived above are deliberately kept: they are correct
		// derivations for real chain positions, and discarding them would turn one
		// forged frame into permanent message loss.
		rollback()
		return nil, err
	}

	// Only now, with the frame proven authentic, is the chain advanced. Advancing
	// earlier would let a single forged frame consume a counter and silently drop
	// the legitimate message that follows.
	next, err := AdvanceChain(s.ckRecv)
	if err != nil {
		return nil, err
	}
	Zero(s.ckRecv)
	s.ckRecv = next
	s.nr = hdr.Counter + 1

	return plaintext, nil
}

// openLocked decrypts and unpads one frame with an already-derived message key.
func (s *Session) openLocked(profile AEADProfile, mk *MessageKey, hdr Header, ciphertext []byte) ([]byte, error) {
	padded, err := profile.Open(mk.Key[:], mk.NonceFor(profile), ciphertext, AssociatedData(s.sessionAD, hdr))
	if err != nil {
		return nil, err
	}
	defer Zero(padded)

	// Unpad copies, so scrubbing the padded buffer afterwards is safe.
	return Unpad(padded)
}

// dhRatchetReceivingLocked installs a new receiving chain after the peer's ratchet
// key changed, then immediately generates a fresh sending chain.
//
// The two steps always go together in the Double Ratchet: receiving a new remote
// key is what entitles us to ratchet our own sending chain, and doing so is what
// gives the session post-compromise security in both directions.
func (s *Session) dhRatchetReceivingLocked(newRemote []byte) error {
	if len(newRemote) != X25519KeySize {
		return fmt.Errorf("%w: ratchet public value must be %d bytes, got %d",
			ErrBadKeySize, X25519KeySize, len(newRemote))
	}
	if s.dhSelfPriv == nil {
		return fmt.Errorf("scs1: no local ratchet key")
	}

	// The previous sending chain becomes the "previous chain": its length is what
	// tells the peer how many keys to cache when it follows our new ratchet key.
	s.pn = s.ns
	s.ns = 0
	s.nr = 0
	s.dhRemote = append([]byte(nil), newRemote...)
	s.hasRemote = true

	dhRecv, err := X25519(s.dhSelfPriv, newRemote)
	if err != nil {
		return err
	}
	defer Zero(dhRecv)

	newRK, ckRecv, err := kdfRootKey(s.rootKey[:], dhRecv)
	if err != nil {
		return err
	}
	if len(s.ckRecv) > 0 {
		Zero(s.ckRecv)
	}
	s.rootKey = newRK
	s.ckRecv = ckRecv

	return s.ratchetSendingChainLocked()
}

// ratchetSendingChainLocked generates a new sending ratchet key pair and chain.
//
// The caller has already recorded the previous chain length and reset the
// counters; this function only performs the key material change.
func (s *Session) ratchetSendingChainLocked() error {
	if !s.hasRemote || len(s.dhRemote) == 0 {
		return fmt.Errorf("scs1: cannot ratchet without a remote ratchet key")
	}

	priv, err := GenerateX25519Key()
	if err != nil {
		return err
	}
	pub := X25519PublicBytes(priv)

	dhSend, err := X25519(priv, s.dhRemote)
	if err != nil {
		return err
	}
	defer Zero(dhSend)

	newRK, ckSend, err := kdfRootKey(s.rootKey[:], dhSend)
	if err != nil {
		return err
	}

	if len(s.ckSend) > 0 {
		Zero(s.ckSend)
	}
	s.rootKey = newRK
	s.ckSend = ckSend
	s.dhSelfPriv = priv
	s.dhSelfPub = pub
	s.lastRatchet = time.Now()

	return nil
}

// skipMessageKeysLocked derives and caches the message keys for counters
// [nr, until), then leaves nr at until.
//
// This is what makes unreliable transport usable: a message that arrives out of
// order is not lost, because its key was set aside when we moved past it.
func (s *Session) skipMessageKeysLocked(until uint32) error {
	if until <= s.nr {
		return nil
	}
	if len(s.ckRecv) == 0 {
		// Nothing to skip yet. The receiving chain is installed by the DH ratchet
		// that follows in DecryptMessage.
		return nil
	}

	gap := uint64(until) - uint64(s.nr)
	if gap > MaxSkippedKeys {
		return fmt.Errorf("%w: gap %d exceeds %d", ErrTooManySkipped, gap, MaxSkippedKeys)
	}

	for s.nr < until {
		mk, err := DeriveMessageKey(s.ckRecv, s.recvDir, uint64(s.nr))
		if err != nil {
			return err
		}
		next, err := AdvanceChain(s.ckRecv)
		if err != nil {
			mk.Zero()
			return err
		}
		Zero(s.ckRecv)
		s.ckRecv = next

		s.storeSkippedLocked(s.dhRemote, s.nr, mk)
		s.nr++
	}
	return nil
}

// storeSkippedLocked caches a message key, evicting the oldest when full.
//
// Eviction is the point of the bound: an attacker who forges ever-larger counters
// can push real keys out of the cache but cannot make the cache grow, so the worst
// case is a lost message rather than an out-of-memory kill.
func (s *Session) storeSkippedLocked(ratchetPub []byte, counter uint32, mk *MessageKey) {
	var key skippedKey
	key.counter = counter
	copy(key.ratchet[:], ratchetPub)

	if old, exists := s.skipped[key]; exists {
		old.Zero()
	}
	s.skipped[key] = mk
	s.skippedOrder = append(s.skippedOrder, key)

	for len(s.skippedOrder) > MaxSkippedKeys {
		oldest := s.skippedOrder[0]
		s.skippedOrder = s.skippedOrder[1:]
		if victim, exists := s.skipped[oldest]; exists {
			victim.Zero()
			delete(s.skipped, oldest)
		}
	}
}

// takeSkippedLocked removes and returns a cached message key, or nil.
func (s *Session) takeSkippedLocked(ratchetPub []byte, counter uint32) *MessageKey {
	var key skippedKey
	key.counter = counter
	copy(key.ratchet[:], ratchetPub)

	mk, exists := s.skipped[key]
	if !exists {
		return nil
	}
	delete(s.skipped, key)
	return mk
}

// SendCounter reports how many messages have been sent in the current chain.
func (s *Session) SendCounter() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ns
}

// RecvCounter reports the expected counter of the next in-order message.
func (s *Session) RecvCounter() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nr
}

// SkippedKeyCount reports how many out-of-order message keys are cached.
func (s *Session) SkippedKeyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.skipped)
}

// RatchetPublic returns the session's current sending ratchet public key.
//
// It is exported for tests and diagnostics: a changing value is the observable
// evidence that the DH ratchet is doing its job.
func (s *Session) RatchetPublic() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.dhSelfPub...)
}

// Close scrubs the session's key material.
//
// # An honest limitation
//
// crypto/ecdh deliberately offers no way to zero a private key: Bytes returns a
// copy and the internal scalar is not exposed. Dropping the reference makes the
// ratchet key eligible for collection but does not scrub it, so a memory image
// captured before the garbage collector runs could still contain it. Every other
// secret in this session is scrubbed explicitly. This is the one place where the
// standard library's API shape limits what can be guaranteed, and it is recorded
// here rather than papered over.
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rootKey.Zero()
	Zero(s.ckSend)
	Zero(s.ckRecv)
	Zero(s.dhSelfPub)
	Zero(s.dhRemote)
	Zero(s.sessionAD)

	for key, mk := range s.skipped {
		mk.Zero()
		delete(s.skipped, key)
	}
	s.skippedOrder = nil

	s.dhSelfPriv = nil
	s.hasRemote = false
}
