package protocol

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Session establishment — SCS-HSK (SCHAT.md section 4.4).
//
// This is a quadruple Diffie-Hellman handshake with two deliberate departures
// from the textbook arrangement:
//
//  1. The DH outputs are sorted lexicographically before hashing (LEXSORT).
//     Textbook implementations concatenate them in role order, which means a
//     client that confuses initiator and responder derives a different root key
//     and the two sides silently fail to talk. Sorting removes that entire class
//     of implementation bug.
//
//  2. The handshake transcript (version, both identity keys, the signed prekey
//     and the one-time prekey actually consumed) is folded into the HKDF salt.
//     Substituting any of those values changes the root key, so a
//     man-in-the-middle cannot survive unnoticed.
//
// Neither departure invents a primitive. Both are composition choices, which is
// exactly where SCS-1's originality is deliberately located.

// HandshakeInitSize is the fixed wire size of a handshake initiation message.
const HandshakeInitSize = 138

// initFlagUsedOneTimePreKey records that the initiator consumed a one-time
// prekey, which gives the session's first message full forward secrecy.
const initFlagUsedOneTimePreKey byte = 1 << 0

// RootKey is the 256-bit session root key.
type RootKey [RootKeySize]byte

// Zero scrubs the root key.
func (r *RootKey) Zero() { Zero(r[:]) }

// IdentityKeyPair is a long-term identity: an Ed25519 signing key and an X25519
// key-agreement key, kept separate so that a flaw in one cannot compromise the
// other.
type IdentityKeyPair struct {
	SigningPrivate   []byte
	SigningPublic    []byte
	AgreementPrivate []byte
	AgreementPublic  []byte
}

// Zero scrubs the private halves of the identity pair.
func (k *IdentityKeyPair) Zero() {
	Zero(k.SigningPrivate)
	Zero(k.AgreementPrivate)
}

// PreKeyBundle is the public material a peer publishes so that others can start a
// session while they are offline.
type PreKeyBundle struct {
	IdentitySigning       []byte
	IdentityAgreement     []byte
	SignedPreKey          []byte
	SignedPreKeyID        uint32
	SignedPreKeySignature []byte
	OneTimePreKey         []byte
	OneTimePreKeyID       uint32
}

// Validate checks that a bundle is structurally usable.
//
// It deliberately does NOT check the signature: EstablishSession does that, and
// keeping verification at the point of use means a caller cannot accidentally
// skip it by forgetting to call Validate.
func (b PreKeyBundle) Validate() error {
	switch {
	case len(b.IdentitySigning) != Ed25519PublicKeySize:
		return fmt.Errorf("%w: bundle identity signing key must be %d bytes, got %d",
			ErrBadKeySize, Ed25519PublicKeySize, len(b.IdentitySigning))
	case len(b.IdentityAgreement) != X25519KeySize:
		return fmt.Errorf("%w: bundle identity agreement key must be %d bytes, got %d",
			ErrBadKeySize, X25519KeySize, len(b.IdentityAgreement))
	case len(b.SignedPreKey) != X25519KeySize:
		return fmt.Errorf("%w: bundle signed prekey must be %d bytes, got %d",
			ErrBadKeySize, X25519KeySize, len(b.SignedPreKey))
	case len(b.SignedPreKeySignature) != Ed25519SignatureSize:
		return fmt.Errorf("%w: bundle signed prekey signature must be %d bytes, got %d",
			ErrBadKeySize, Ed25519SignatureSize, len(b.SignedPreKeySignature))
	case b.OneTimePreKey != nil && len(b.OneTimePreKey) != X25519KeySize:
		return fmt.Errorf("%w: bundle one-time prekey must be %d bytes, got %d",
			ErrBadKeySize, X25519KeySize, len(b.OneTimePreKey))
	}
	return nil
}

// PreKeyStore holds the private half of an identity's published prekey material.
//
// A one-time prekey is consumed exactly once and then cannot be recovered. That
// single use is the whole point: it is what gives the session's opening message
// forward secrecy against a later compromise of the signed prekey.
type PreKeyStore struct {
	// SignedPreKeyID identifies the current signed prekey.
	SignedPreKeyID uint32

	// SignedPreKeyPrivate and SignedPreKeyPublic are the X25519 pair.
	SignedPreKeyPrivate []byte
	SignedPreKeyPublic  []byte

	// SignedPreKeySignature is the Ed25519 signature over SignedPreKeyPublic.
	SignedPreKeySignature []byte

	// oneTimePrivates maps prekey id to X25519 private scalar.
	oneTimePrivates map[uint32][]byte

	// oneTimePublics maps prekey id to its public value, for bundle generation.
	oneTimePublics map[uint32][]byte
}

// NewPreKeyStore generates an identity's prekey material.
//
// count bounds the one-time prekey pool. It is capped rather than unbounded so
// that the published bundle cannot be inflated without limit.
func NewPreKeyStore(identity *IdentityKeyPair, count int) (*PreKeyStore, error) {
	if identity == nil {
		return nil, fmt.Errorf("scs1: nil identity")
	}
	if count < 0 || count > 1000 {
		return nil, fmt.Errorf("scs1: one-time prekey count %d out of range 0..1000", count)
	}

	spkPriv, err := GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	spkPub := X25519PublicBytes(spkPriv)

	sig, err := identity.Sign(spkPub)
	if err != nil {
		return nil, err
	}

	store := &PreKeyStore{
		SignedPreKeyID:        1,
		SignedPreKeyPrivate:   spkPriv.Bytes(),
		SignedPreKeyPublic:    spkPub,
		SignedPreKeySignature: sig,
		oneTimePrivates:       make(map[uint32][]byte, count),
		oneTimePublics:        make(map[uint32][]byte, count),
	}

	for i := 0; i < count; i++ {
		id := uint32(i + 1)
		priv, err := GenerateX25519Key()
		if err != nil {
			return nil, err
		}
		store.oneTimePrivates[id] = priv.Bytes()
		store.oneTimePublics[id] = X25519PublicBytes(priv)
	}

	return store, nil
}

// OneTimePreKeyIDs returns the ids currently available, ascending.
func (s *PreKeyStore) OneTimePreKeyIDs() []uint32 {
	ids := make([]uint32, 0, len(s.oneTimePublics))
	for id := range s.oneTimePublics {
		ids = append(ids, id)
	}
	// Insertion sort: the pool is small and this keeps the output deterministic,
	// which the tests rely on.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j-1] > ids[j]; j-- {
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
	return ids
}

// Bundle builds the publishable bundle, optionally attaching one one-time prekey.
//
// Pass oneTimePreKeyID = 0 to publish without a one-time prekey. That is a
// legitimate degraded mode: the session still works, it simply loses forward
// secrecy for its first message.
func (s *PreKeyStore) Bundle(identity *IdentityKeyPair, oneTimePreKeyID uint32) (PreKeyBundle, error) {
	if identity == nil {
		return PreKeyBundle{}, fmt.Errorf("scs1: nil identity")
	}

	b := PreKeyBundle{
		IdentitySigning:       identity.SigningPublic,
		IdentityAgreement:     identity.AgreementPublic,
		SignedPreKey:          s.SignedPreKeyPublic,
		SignedPreKeyID:        s.SignedPreKeyID,
		SignedPreKeySignature: s.SignedPreKeySignature,
	}

	if oneTimePreKeyID != 0 {
		pub, ok := s.oneTimePublics[oneTimePreKeyID]
		if !ok {
			return PreKeyBundle{}, fmt.Errorf("scs1: one-time prekey %d is not available", oneTimePreKeyID)
		}
		b.OneTimePreKey = pub
		b.OneTimePreKeyID = oneTimePreKeyID
	}

	return b, nil
}

// takeOneTimePreKey removes a prekey and returns both halves.
//
// Both halves must be returned together and before the private scalar is used:
// ConsumeOneTimePreKey deletes the public value as well, and the responder needs
// it to rebuild the handshake transcript exactly as the initiator built it.
// Splitting the lookup from the removal caused a real bug during development, so
// the two are now inseparable.
func (s *PreKeyStore) takeOneTimePreKey(id uint32) (public, private []byte, ok bool) {
	priv, ok := s.oneTimePrivates[id]
	if !ok {
		return nil, nil, false
	}
	pub := s.oneTimePublics[id]

	delete(s.oneTimePrivates, id)
	delete(s.oneTimePublics, id)

	return pub, priv, true
}

// ConsumeOneTimePreKey removes a one-time prekey and returns its private scalar.
//
// Removal is a security property. A prekey that could be fetched twice would let
// two sessions share the same DH input, which is precisely what the one-time pool
// exists to prevent.
func (s *PreKeyStore) ConsumeOneTimePreKey(id uint32) ([]byte, bool) {
	_, priv, ok := s.takeOneTimePreKey(id)
	return priv, ok
}

// ExportOneTimePreKey returns both halves of a one-time prekey WITHOUT consuming it.
//
// It exists for persistence: the client has to write its whole prekey pool into its
// encrypted vault and read it back later. Consumption is a separate, deliberate act
// (ConsumeOneTimePreKey) precisely so that "export for storage" can never be confused
// with "use once".
func (s *PreKeyStore) ExportOneTimePreKey(id uint32) (public, private []byte, ok bool) {
	priv, found := s.oneTimePrivates[id]
	if !found {
		return nil, nil, false
	}
	pub := s.oneTimePublics[id]
	return append([]byte(nil), pub...), append([]byte(nil), priv...), true
}

// NewPreKeyStoreFromParts rebuilds a store from persisted material.
//
// It exists because the client stores its prekeys in its own vault rather than
// keeping them in Go memory across restarts. The constructor performs the structural
// validation that a JSON round trip cannot: a store with a prekey in one map but not
// the other would otherwise produce an inexplicable handshake failure much later.
func NewPreKeyStoreFromParts(
	id uint32,
	signedPreKeyPrivate, signedPreKeyPublic, signedPreKeySignature []byte,
	oneTimePrivates, oneTimePublics map[uint32][]byte,
) *PreKeyStore {
	privates := make(map[uint32][]byte, len(oneTimePrivates))
	for k, v := range oneTimePrivates {
		privates[k] = append([]byte(nil), v...)
	}
	publics := make(map[uint32][]byte, len(oneTimePublics))
	for k, v := range oneTimePublics {
		publics[k] = append([]byte(nil), v...)
	}

	// Drop any prekey that is missing one of its halves, rather than leaving a
	// landmine in the pool.
	for k := range privates {
		if _, ok := publics[k]; !ok {
			delete(privates, k)
		}
	}
	for k := range publics {
		if _, ok := privates[k]; !ok {
			delete(publics, k)
		}
	}

	return &PreKeyStore{
		SignedPreKeyID:        id,
		SignedPreKeyPrivate:   append([]byte(nil), signedPreKeyPrivate...),
		SignedPreKeyPublic:    append([]byte(nil), signedPreKeyPublic...),
		SignedPreKeySignature: append([]byte(nil), signedPreKeySignature...),
		oneTimePrivates:       privates,
		oneTimePublics:        publics,
	}
}

// Zero scrubs every private value in the store.
func (s *PreKeyStore) Zero() {
	if s == nil {
		return
	}
	Zero(s.SignedPreKeyPrivate)
	for id, priv := range s.oneTimePrivates {
		Zero(priv)
		delete(s.oneTimePrivates, id)
	}
}

// HandshakeInit is what an initiator sends to open a session.
//
// It carries only public values. Its authenticity comes from being bound into the
// transcript that both sides fold into the root key, not from a signature: an
// attacker can forge an Init message, but the two peers will then derive
// different root keys and the session fails closed.
type HandshakeInit struct {
	IdentitySigning   []byte
	IdentityAgreement []byte
	Ephemeral         []byte
	SignedPreKeyID    uint32
	OneTimePreKeyID   uint32
	UsedOneTimePreKey bool

	// RatchetPublic is the initiator's first DH ratchet public key. Sending it
	// here saves a round trip: the responder can initialise its receiving chain
	// immediately instead of waiting for the first ciphertext.
	RatchetPublic []byte
}

// Marshal encodes the handshake initiation to its fixed 138-byte form.
func (h *HandshakeInit) Marshal() []byte {
	out := make([]byte, HandshakeInitSize)
	out[0] = WireVersion
	if h.UsedOneTimePreKey {
		out[1] = initFlagUsedOneTimePreKey
	}
	copy(out[2:34], h.IdentitySigning)
	copy(out[34:66], h.IdentityAgreement)
	copy(out[66:98], h.Ephemeral)
	binary.BigEndian.PutUint32(out[98:102], h.SignedPreKeyID)
	binary.BigEndian.PutUint32(out[102:106], h.OneTimePreKeyID)
	copy(out[106:138], h.RatchetPublic)
	return out
}

// UnmarshalHandshakeInit decodes a handshake initiation.
//
// Every field is length-checked before use. Parsing untrusted network input is
// where a bounds bug would do the most damage, so this function never indexes
// without having established the bound first, and it copies each field rather
// than aliasing the caller's buffer.
func UnmarshalHandshakeInit(b []byte) (*HandshakeInit, error) {
	if len(b) < HandshakeInitSize {
		return nil, fmt.Errorf("%w: handshake init needs %d bytes, got %d",
			ErrShortBuffer, HandshakeInitSize, len(b))
	}
	if b[0] != WireVersion {
		return nil, fmt.Errorf("%w: handshake init version %d, want %d",
			ErrUnknownVersion, b[0], WireVersion)
	}

	return &HandshakeInit{
		IdentitySigning:   append([]byte(nil), b[2:34]...),
		IdentityAgreement: append([]byte(nil), b[34:66]...),
		Ephemeral:         append([]byte(nil), b[66:98]...),
		SignedPreKeyID:    binary.BigEndian.Uint32(b[98:102]),
		OneTimePreKeyID:   binary.BigEndian.Uint32(b[102:106]),
		RatchetPublic:     append([]byte(nil), b[106:138]...),
		UsedOneTimePreKey: b[1]&initFlagUsedOneTimePreKey != 0,
	}, nil
}

// deriveRootKey computes the session root key:
//
//	material = LEXSORT(DH1..DH4) concatenated
//	salt     = LabelRoot || LE64(epoch) || transcript
//	RK       = HKDF-SHA256(material, salt, LabelRoot, 32)
func deriveRootKey(material [][]byte, transcript []byte, epoch uint64) (RootKey, error) {
	var rk RootKey

	sorted := LexSort(material...)
	ikm := concat(sorted...)
	defer Zero(ikm)

	salt := make([]byte, 0, len(LabelRoot)+8+len(transcript))
	salt = append(salt, LabelRoot...)
	salt = binary.LittleEndian.AppendUint64(salt, epoch)
	salt = append(salt, transcript...)

	out, err := HKDF(ikm, salt, LabelRoot, RootKeySize)
	if err != nil {
		return rk, err
	}
	defer Zero(out)

	copy(rk[:], out)
	return rk, nil
}

// kdfRootKey performs one DH ratchet step:
//
//	(RK', CK) = HKDF-SHA256(ikm = dhOut, salt = RK, info = LabelChain, len = 64)
//
// The DH output is the input keying material and the current root key is the salt,
// which is the standard Double Ratchet arrangement: each step mixes fresh DH
// entropy into the root key, and neither the old root key nor the DH output alone
// reveals the new one.
func kdfRootKey(rk []byte, dhOut []byte) (newRoot RootKey, chainKey []byte, err error) {
	out, err := HKDF(dhOut, rk, LabelChain, RootKeySize+ChainKeySize)
	if err != nil {
		return newRoot, nil, err
	}
	defer Zero(out)

	copy(newRoot[:], out[:RootKeySize])
	chainKey = append([]byte(nil), out[RootKeySize:]...)
	return newRoot, chainKey, nil
}

// Session is an established SCS-1 session.
//
// It holds ratchet state and therefore must never be copied after first use and
// must be Close()d when discarded. All methods are safe for concurrent use: a UI
// thread and a network goroutine both touch it.
type Session struct {
	mu sync.Mutex

	// rootKey is the current 256-bit root key.
	rootKey RootKey

	// sendDir and recvDir are this session's direction bytes. They differ between
	// the two peers, which is what makes a reflected ciphertext fail to decrypt.
	sendDir byte
	recvDir byte

	// sessionAD is derived from the handshake transcript and prepended to every
	// frame's associated data, so a ciphertext cannot be moved between sessions.
	sessionAD []byte

	// peerSigning is the peer's identity signing public key: taken from the bundle
	// on the initiator's side, carried in the handshake initiation on the
	// responder's side.
	//
	// It is public material — that is the entire point of an identity key — and it
	// is retained so that BOTH peers can compute the safety number. Without it only
	// the initiator could, since only the initiator ever fetched a bundle, and a
	// verification ritual that one side cannot perform proves nothing to that side.
	peerSigning []byte

	// DH ratchet state.
	dhSelfPriv *ecdh.PrivateKey
	dhSelfPub  []byte
	dhRemote   []byte
	hasRemote  bool

	// Symmetric ratchet state.
	ckSend []byte
	ckRecv []byte

	// ns is the number of messages sent in the current sending chain, nr the
	// number received, pn the length of the previous sending chain.
	ns uint32
	nr uint32
	pn uint32

	// lastRatchet records when the sending chain last received new DH entropy.
	lastRatchet time.Time

	// skipped holds message keys for messages that have not arrived yet, keyed by
	// the ratchet public key and counter they belong to.
	skipped map[skippedKey]*MessageKey

	// skippedOrder is the insertion order used to evict the oldest skipped key
	// once the cache is full.
	skippedOrder []skippedKey
}

// PeerIdentitySigning returns the peer's identity signing public key.
//
// This is the value the safety number is computed from, and both sides can produce
// it: the initiator took it from the bundle it fetched, the responder from the
// handshake initiation. It is public key material, so unlike the ratchet state there
// is no reason to zero it, and returning a copy keeps a caller from mutating session
// state.
func (s *Session) PeerIdentitySigning() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.peerSigning...)
}

// skippedKey identifies one undelivered message.
type skippedKey struct {
	ratchet [RatchetPubSize]byte
	counter uint32
}

// EstablishSession performs SCS-HSK as the initiator.
//
// It returns the live session plus the initiation message to transmit. The
// initiator can encrypt immediately, because its sending chain is initialised by
// the first DH ratchet step performed here.
func EstablishSession(me *IdentityKeyPair, peer PreKeyBundle) (*Session, *HandshakeInit, error) {
	if me == nil {
		return nil, nil, fmt.Errorf("scs1: nil identity")
	}
	if err := peer.Validate(); err != nil {
		return nil, nil, err
	}

	// The signed prekey must carry a valid signature from the peer's identity
	// key. Without this check an attacker could substitute their own prekey, and
	// the transcript binding alone would not help because the transcript would
	// consistently contain the attacker's value.
	if err := Verify(peer.IdentitySigning, peer.SignedPreKey, peer.SignedPreKeySignature); err != nil {
		return nil, nil, fmt.Errorf("%w: signed prekey signature", err)
	}

	ikPriv, err := me.AgreementPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	ek, err := GenerateX25519Key()
	if err != nil {
		return nil, nil, err
	}

	dh1, err := X25519(ikPriv, peer.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	defer Zero(dh1)

	dh2, err := X25519(ek, peer.IdentityAgreement)
	if err != nil {
		return nil, nil, err
	}
	defer Zero(dh2)

	dh3, err := X25519(ek, peer.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	defer Zero(dh3)

	material := [][]byte{dh1, dh2, dh3}
	if len(peer.OneTimePreKey) > 0 {
		dh4, err := X25519(ikPriv, peer.OneTimePreKey)
		if err != nil {
			return nil, nil, err
		}
		defer Zero(dh4)
		// deriveRootKey sorts the material, so slice order does not matter.
		material = append(material, dh4)
	}

	transcript := HandshakeTranscript(
		WireVersion,
		me.AgreementPublic,
		peer.IdentityAgreement,
		peer.SignedPreKey,
		peer.OneTimePreKey,
	)

	rk, err := deriveRootKey(material, transcript, 0)
	if err != nil {
		return nil, nil, err
	}
	defer rk.Zero()

	// First DH ratchet step. The peer's signed prekey plays the role of the
	// initial remote ratchet key, so the responder can recompute the same shared
	// secret from its own signed prekey private value.
	ratchetPriv, err := GenerateX25519Key()
	if err != nil {
		return nil, nil, err
	}
	ratchetPub := X25519PublicBytes(ratchetPriv)

	dhOut, err := X25519(ratchetPriv, peer.SignedPreKey)
	if err != nil {
		return nil, nil, err
	}
	defer Zero(dhOut)

	newRK, ckSend, err := kdfRootKey(rk[:], dhOut)
	if err != nil {
		return nil, nil, err
	}

	s := &Session{
		rootKey:     newRK,
		sendDir:     DirAToB,
		recvDir:     DirBToA,
		sessionAD:   append([]byte(nil), transcript...),
		peerSigning: append([]byte(nil), peer.IdentitySigning...),
		dhSelfPriv:  ratchetPriv,
		dhSelfPub:   ratchetPub,
		dhRemote:    append([]byte(nil), peer.SignedPreKey...),
		hasRemote:   true,
		ckSend:      ckSend,
		lastRatchet: time.Now(),
		skipped:     make(map[skippedKey]*MessageKey),
	}

	init := &HandshakeInit{
		IdentitySigning:   me.SigningPublic,
		IdentityAgreement: me.AgreementPublic,
		Ephemeral:         X25519PublicBytes(ek),
		SignedPreKeyID:    peer.SignedPreKeyID,
		OneTimePreKeyID:   peer.OneTimePreKeyID,
		UsedOneTimePreKey: len(peer.OneTimePreKey) > 0,
		RatchetPublic:     ratchetPub,
	}

	return s, init, nil
}

// AcceptSession performs SCS-HSK as the responder.
//
// The one-time prekey named in the initiation is consumed from the store, so the
// same prekey can never be used for a second session.
func AcceptSession(me *IdentityKeyPair, store *PreKeyStore, init *HandshakeInit) (*Session, error) {
	if me == nil || store == nil || init == nil {
		return nil, fmt.Errorf("scs1: nil identity, store or handshake message")
	}
	if init.SignedPreKeyID != store.SignedPreKeyID {
		return nil, fmt.Errorf("scs1: handshake names signed prekey %d but this store holds %d",
			init.SignedPreKeyID, store.SignedPreKeyID)
	}
	if len(init.Ephemeral) != X25519KeySize || len(init.RatchetPublic) != X25519KeySize {
		return nil, fmt.Errorf("%w: malformed handshake public values", ErrBadKeySize)
	}
	if len(init.IdentityAgreement) != X25519KeySize {
		return nil, fmt.Errorf("%w: malformed initiator identity key", ErrBadKeySize)
	}

	// Resolve the one-time prekey FIRST. Its public value is needed to rebuild
	// the transcript, and taking it removes both halves from the store, so the
	// two facts must be captured together and before anything else consumes them.
	var opkPublic, opkPrivate []byte
	if init.UsedOneTimePreKey {
		pub, priv, ok := store.takeOneTimePreKey(init.OneTimePreKeyID)
		if !ok {
			// The initiator used a one-time prekey this store no longer holds.
			// Continuing without it would derive a different root key and the
			// failure would surface much later as an inexplicable authentication
			// error. Failing now is clearer and safer.
			return nil, fmt.Errorf("scs1: one-time prekey %d is unavailable or already used",
				init.OneTimePreKeyID)
		}
		opkPublic, opkPrivate = pub, priv
		defer Zero(opkPrivate)
	}

	spkPriv, err := X25519FromBytes(store.SignedPreKeyPrivate)
	if err != nil {
		return nil, err
	}
	ikPriv, err := me.AgreementPrivateKey()
	if err != nil {
		return nil, err
	}

	// Mirror the initiator's DH inputs. Each is recomputed from the other side of
	// the same exchange, so both parties arrive at identical values:
	//
	//	DH1 = DH(IK_dh_A, SPK_B)   ->   DH(spk_B, IK_dh_A)
	//	DH2 = DH(EK_A,    IK_dh_B) ->   DH(ik_dh_B, EK_A)
	//	DH3 = DH(EK_A,    SPK_B)   ->   DH(spk_B, EK_A)
	//	DH4 = DH(IK_dh_A, OPK_B)   ->   DH(opk_B, IK_dh_A)
	dh1, err := X25519(spkPriv, init.IdentityAgreement)
	if err != nil {
		return nil, err
	}
	defer Zero(dh1)

	dh2, err := X25519(ikPriv, init.Ephemeral)
	if err != nil {
		return nil, err
	}
	defer Zero(dh2)

	dh3, err := X25519(spkPriv, init.Ephemeral)
	if err != nil {
		return nil, err
	}
	defer Zero(dh3)

	material := [][]byte{dh1, dh2, dh3}

	if len(opkPublic) > 0 {
		// DH4 = DH(IK_dh_A, OPK_B) on the initiator's side is, from here, the
		// one-time prekey's PRIVATE value against the initiator's identity public
		// value. Using our own identity key against our own prekey public value
		// would be a self-DH: it computes cleanly, produces a plausible-looking
		// root key, and silently disagrees with the peer. That mistake was made and
		// caught here by the interoperability test, which is the whole reason that
		// test exists.
		opkPrivKey, err := X25519FromBytes(opkPrivate)
		if err != nil {
			return nil, err
		}
		dh4, err := X25519(opkPrivKey, init.IdentityAgreement)
		if err != nil {
			return nil, err
		}
		defer Zero(dh4)
		material = append(material, dh4)
	}

	transcript := HandshakeTranscript(
		WireVersion,
		init.IdentityAgreement,
		me.AgreementPublic,
		store.SignedPreKeyPublic,
		opkPublic,
	)

	rk, err := deriveRootKey(material, transcript, 0)
	if err != nil {
		return nil, err
	}
	defer rk.Zero()

	// Receiving chain: the initiator already ratcheted against our signed prekey,
	// so that same shared secret yields our receiving chain.
	dhRecv, err := X25519(spkPriv, init.RatchetPublic)
	if err != nil {
		return nil, err
	}
	defer Zero(dhRecv)

	rkAfterRecv, ckRecv, err := kdfRootKey(rk[:], dhRecv)
	if err != nil {
		return nil, err
	}

	// Sending chain: generate our own ratchet key pair, exactly as the initiator
	// does when it sees a new remote ratchet key.
	ratchetPriv, err := GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	ratchetPub := X25519PublicBytes(ratchetPriv)

	dhSend, err := X25519(ratchetPriv, init.RatchetPublic)
	if err != nil {
		return nil, err
	}
	defer Zero(dhSend)

	newRK, ckSend, err := kdfRootKey(rkAfterRecv[:], dhSend)
	if err != nil {
		return nil, err
	}

	s := &Session{
		rootKey:     newRK,
		sendDir:     DirBToA,
		recvDir:     DirAToB,
		sessionAD:   append([]byte(nil), transcript...),
		peerSigning: append([]byte(nil), init.IdentitySigning...),
		dhSelfPriv:  ratchetPriv,
		dhSelfPub:   ratchetPub,
		dhRemote:    append([]byte(nil), init.RatchetPublic...),
		hasRemote:   true,
		ckRecv:      ckRecv,
		ckSend:      ckSend,
		lastRatchet: time.Now(),
		skipped:     make(map[skippedKey]*MessageKey),
	}

	return s, nil
}
