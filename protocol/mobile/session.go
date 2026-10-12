package mobile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/schat/schat/protocol"
)

// The session API exposed to the client.
//
// It lives in its own file because it is a different kind of surface from the
// onboarding material in mobile.go: these calls hold live ratchet state across the
// binding, and getting that state wrong is not a cosmetic failure — it is every message
// failing to decrypt for reasons no error message can explain.
//
// # Lifecycle
//
//	initiator:  EstablishSession -> InitMessage() -> (transmit) -> Encrypt/Decrypt
//	responder:  AcceptSession(initMessage) -> Encrypt/Decrypt
//	either:     Snapshot() -> (store in the encrypted vault) -> RestoreSession(...)
//
// A Session must be Close()d when discarded. The snapshot is key material and must be
// encrypted by the caller before it touches storage; see protocol/session_state.go.

// Content types that may follow the delivery token in a relay payload.
//
//	token (16) || content type (1) || payload
//
// # Why a type byte is needed at all
//
// The relay forwards opaque bytes, and the handshake initiation is not an encrypted
// frame — it is 138 bytes of public key material that has to reach a peer before any
// session exists. Without a discriminator, a client could not tell an incoming handshake
// from an incoming message, and the very first thing two peers exchange would have no
// way to travel.
//
// The handshake initiation is plaintext on the wire, and that is by design rather than
// an oversight: it contains only public values, and its authenticity comes from being
// folded into the transcript that both sides mix into the root key (SCHAT.md section
// 4.4). Anyone may read it; nobody can forge one that both peers will accept.
const (
	// ContentTypeFrame is an SCS-1 encrypted frame.
	ContentTypeFrame byte = 0x01

	// ContentTypeHandshake is a plaintext session initiation.
	ContentTypeHandshake byte = 0x02
)

// ContentType reports which kind of payload a relay envelope carries.
func ContentType(wire []byte) (byte, error) {
	if len(wire) < protocol.TokenSize+1 {
		return 0, fmt.Errorf("scs1: relay payload is shorter than a token and a content type")
	}
	return wire[protocol.TokenSize], nil
}

// WrapHandshake addresses a handshake initiation to a mailbox.
//
// It is a separate call from Encrypt because it needs no session: the whole point of a
// handshake is that no session exists yet.
func WrapHandshake(tokenHex string, initMessage []byte) ([]byte, error) {
	token, err := decodeToken(tokenHex)
	if err != nil {
		return nil, err
	}
	if len(initMessage) != protocol.HandshakeInitSize {
		return nil, fmt.Errorf("scs1: handshake initiation must be %d bytes, got %d",
			protocol.HandshakeInitSize, len(initMessage))
	}

	out := make([]byte, 0, protocol.TokenSize+1+len(initMessage))
	out = append(out, token...)
	out = append(out, ContentTypeHandshake)
	out = append(out, initMessage...)
	return out, nil
}

// UnwrapHandshake extracts a handshake initiation from a relay payload.
func UnwrapHandshake(wire []byte) ([]byte, error) {
	kind, err := ContentType(wire)
	if err != nil {
		return nil, err
	}
	if kind != ContentTypeHandshake {
		return nil, fmt.Errorf("scs1: relay payload carries content type %d, not a handshake", kind)
	}
	return append([]byte(nil), wire[protocol.TokenSize+1:]...), nil
}

// decodeToken validates a hex delivery token.
func decodeToken(tokenHex string) ([]byte, error) {
	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("scs1: delivery token is not valid hex: %w", err)
	}
	if len(token) != protocol.TokenSize {
		return nil, fmt.Errorf("scs1: delivery token must be %d bytes, got %d",
			protocol.TokenSize, len(token))
	}
	return token, nil
}

// Session is a live ratchet session.
type Session struct {
	s *protocol.Session

	// initMessage holds the handshake initiation until the caller collects it. Keeping
	// it here rather than returning it alongside the session avoids a multi-value return,
	// which gomobile does not support.
	initMessage []byte

	// updatedStore is the responder's prekey pool AFTER the handshake consumed a
	// one-time prekey. The client MUST persist it over the previous pool; see
	// UpdatedPreKeyStore.
	updatedStore string
}

// bundleJSON mirrors the JSON the relay's prekey directory serves.
//
// It is declared here rather than imported from the server so that the client binding
// has no dependency on server code.
type bundleJSON struct {
	IdentitySigning       string `json:"identity_signing"`
	IdentityAgreement     string `json:"identity_agreement"`
	SignedPreKey          string `json:"signed_pre_key"`
	SignedPreKeyID        int64  `json:"signed_pre_key_id"`
	SignedPreKeySignature string `json:"signed_pre_key_signature"`

	// OneTimePreKeys carries at most one entry: the directory consumes a prekey as it
	// hands it out.
	OneTimePreKeys []struct {
		ID     int64  `json:"id"`
		Public string `json:"public"`
	} `json:"one_time_pre_keys"`
}

// EstablishSession performs SCS-HSK as the initiator.
//
// peerIdentityHex is the identity the caller asked the directory for, and the bundle is
// checked against it. That check is not optional: publishing to the directory is
// unauthenticated, so anyone can overwrite an identity's entry with their own keys.
// Without this comparison a substituted bundle would verify perfectly against itself.
func EstablishSession(identityJSON string, peerIdentityHex string, bundleJSONText string) (*Session, error) {
	id, err := identityFromBinding(identityJSON)
	if err != nil {
		return nil, err
	}
	defer id.Zero()

	var parsed bundleJSON
	if err := json.Unmarshal([]byte(bundleJSONText), &parsed); err != nil {
		return nil, fmt.Errorf("scs1: bundle is not valid JSON: %w", err)
	}

	expected := normaliseHex(peerIdentityHex)
	if expected == "" {
		return nil, fmt.Errorf("scs1: the peer identity to expect was not supplied")
	}
	if normaliseHex(parsed.IdentitySigning) != expected {
		return nil, fmt.Errorf(
			"scs1: the directory returned a bundle for identity %s, but %s was requested",
			short(parsed.IdentitySigning), short(expected))
	}

	bundle := protocol.PreKeyBundle{
		IdentitySigning:       decodeHexOrNil(parsed.IdentitySigning),
		IdentityAgreement:     decodeHexOrNil(parsed.IdentityAgreement),
		SignedPreKey:          decodeHexOrNil(parsed.SignedPreKey),
		SignedPreKeyID:        uint32(parsed.SignedPreKeyID),
		SignedPreKeySignature: decodeHexOrNil(parsed.SignedPreKeySignature),
	}
	if len(parsed.OneTimePreKeys) > 0 {
		bundle.OneTimePreKey = decodeHexOrNil(parsed.OneTimePreKeys[0].Public)
		bundle.OneTimePreKeyID = uint32(parsed.OneTimePreKeys[0].ID)
	}

	session, init, err := protocol.EstablishSession(id, bundle)
	if err != nil {
		return nil, err
	}

	return &Session{s: session, initMessage: init.Marshal()}, nil
}

// InitMessage returns the handshake initiation to transmit to the peer.
//
// It is only populated on the initiator's side; a responder's session returns nothing.
func (s *Session) InitMessage() []byte {
	return append([]byte(nil), s.initMessage...)
}

// UpdatedPreKeyStore returns the responder's prekey pool after a handshake consumed one
// of its one-time prekeys, or an empty string for an initiator's session.
//
// # The client MUST persist this
//
// This exists because of a defect the test suite caught: the binding rebuilds the
// prekey store from JSON on every call, so a replayed handshake message would find the
// one-time prekey still present, consume it a second time, and complete a second session
// from the same DH inputs — which is precisely what the one-time pool exists to prevent.
//
// The protocol layer consumes the prekey correctly; the binding has to hand the
// consumed state back so the client can write it over the old pool. Failing to do so
// silently restores the replay.
func (s *Session) UpdatedPreKeyStore() string {
	return s.updatedStore
}

// AcceptSession performs SCS-HSK as the responder.
//
// The one-time prekey named by the initiation is consumed from the store, so a replayed
// handshake fails rather than silently creating a second session with the same inputs.
func AcceptSession(identityJSON string, storeJSON string, initMessage []byte) (*Session, error) {
	id, err := identityFromBinding(identityJSON)
	if err != nil {
		return nil, err
	}
	defer id.Zero()

	store, err := preKeyStoreFromBinding(storeJSON)
	if err != nil {
		return nil, err
	}
	defer store.Zero()

	init, err := protocol.UnmarshalHandshakeInit(initMessage)
	if err != nil {
		return nil, err
	}

	session, err := protocol.AcceptSession(id, store, init)
	if err != nil {
		return nil, err
	}

	// Hand the consumed pool back. Without this the one-time prekey would still be
	// present the next time the client parses its stored JSON, and a replayed handshake
	// would succeed.
	remaining, err := preKeyStoreToBinding(store)
	if err != nil {
		session.Close()
		return nil, err
	}

	return &Session{s: session, updatedStore: remaining}, nil
}

// preKeyStoreToBinding serialises a prekey store, including only the one-time prekeys
// that have not been consumed.
func preKeyStoreToBinding(store *protocol.PreKeyStore) (string, error) {
	out := preKeyStoreJSON{
		SignedPreKeyID:        int64(store.SignedPreKeyID),
		SignedPreKeyPrivate:   hex.EncodeToString(store.SignedPreKeyPrivate),
		SignedPreKeyPublic:    hex.EncodeToString(store.SignedPreKeyPublic),
		SignedPreKeySignature: hex.EncodeToString(store.SignedPreKeySignature),
	}

	for _, id := range store.OneTimePreKeyIDs() {
		public, private, ok := store.ExportOneTimePreKey(id)
		if !ok {
			continue
		}
		out.OneTimeIDs = append(out.OneTimeIDs, int64(id))
		out.OneTimePrivates = append(out.OneTimePrivates, hex.EncodeToString(private))
		out.OneTimePublics = append(out.OneTimePublics, hex.EncodeToString(public))
	}

	raw, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Encrypt produces the bytes to hand to the relay: token || header || ciphertext.
//
// The token is the recipient's current delivery token, in hex. It is the caller's job
// to choose which of the recipient's tokens to use and to keep it fresh; the protocol
// layer has no opinion about routing.
func (s *Session) Encrypt(tokenHex string, plaintext []byte, profile string) ([]byte, error) {
	if s == nil || s.s == nil {
		return nil, fmt.Errorf("scs1: nil session")
	}

	token, err := decodeToken(tokenHex)
	if err != nil {
		return nil, err
	}

	aeadProfile, err := profileFor(profile)
	if err != nil {
		return nil, err
	}

	envelope, err := s.s.EncryptMessage(plaintext, aeadProfile)
	if err != nil {
		return nil, err
	}
	copy(envelope.Token[:], token)

	// token || type || header || ciphertext
	frame := envelope.Marshal()
	out := make([]byte, 0, len(frame)+1)
	out = append(out, frame[:protocol.TokenSize]...)
	out = append(out, ContentTypeFrame)
	out = append(out, frame[protocol.TokenSize:]...)
	return out, nil
}

// Decrypt consumes bytes from the relay and returns the plaintext.
//
// The token in the envelope is ignored: it addressed this client's own mailbox on the
// way in, and it carries no meaning once the message has arrived.
func (s *Session) Decrypt(wire []byte) ([]byte, error) {
	if s == nil || s.s == nil {
		return nil, fmt.Errorf("scs1: nil session")
	}

	kind, err := ContentType(wire)
	if err != nil {
		return nil, err
	}
	if kind != ContentTypeFrame {
		return nil, fmt.Errorf("scs1: relay payload carries content type %d, not an encrypted frame", kind)
	}

	// Reassemble token || frame for the protocol decoder.
	frame := make([]byte, 0, len(wire)-1)
	frame = append(frame, wire[:protocol.TokenSize]...)
	frame = append(frame, wire[protocol.TokenSize+1:]...)

	envelope, err := protocol.UnmarshalEnvelope(frame)
	if err != nil {
		return nil, err
	}
	return s.s.DecryptMessage(envelope)
}

// Snapshot serialises the session for storage.
//
// The result is KEY MATERIAL. Encrypt it with the vault before writing it anywhere; see
// protocol/session_state.go for why the format itself cannot protect it.
func (s *Session) Snapshot() ([]byte, error) {
	if s == nil || s.s == nil {
		return nil, fmt.Errorf("scs1: nil session")
	}
	return s.s.Snapshot()
}

// RestoreSession rebuilds a session from a snapshot.
func RestoreSession(snapshot []byte) (*Session, error) {
	session, err := protocol.RestoreSession(snapshot)
	if err != nil {
		return nil, err
	}
	return &Session{s: session}, nil
}

// Close scrubs the session's key material.
func (s *Session) Close() {
	if s == nil || s.s == nil {
		return
	}
	s.s.Close()
	s.s = nil
	s.initMessage = nil
}

// SendCounter reports the number of messages sent in the current chain.
func (s *Session) SendCounter() int64 {
	if s == nil || s.s == nil {
		return 0
	}
	return int64(s.s.SendCounter())
}

// RecvCounter reports the expected counter of the next in-order message.
func (s *Session) RecvCounter() int64 {
	if s == nil || s.s == nil {
		return 0
	}
	return int64(s.s.RecvCounter())
}

// RatchetPublic returns the session's current sending ratchet public key, in hex.
func (s *Session) RatchetPublic() string {
	if s == nil || s.s == nil {
		return ""
	}
	return hex.EncodeToString(s.s.RatchetPublic())
}

// SkippedKeyCount reports how many out-of-order message keys are cached.
func (s *Session) SkippedKeyCount() int64 {
	if s == nil || s.s == nil {
		return 0
	}
	return int64(s.s.SkippedKeyCount())
}

// PeerIdentity returns the peer's identity signing public key, in hex.
//
// The client needs it twice over: to compute the peer's mailbox when addressing a
// handshake, and to derive the 60-digit safety number that both users read aloud. It
// is available on BOTH sides of a session — the initiator from the bundle it fetched,
// the responder from the handshake initiation — and survives a snapshot, so the
// comparison is not a ritual only one participant can perform.
func (s *Session) PeerIdentity() string {
	if s == nil || s.s == nil {
		return ""
	}
	return hex.EncodeToString(s.s.PeerIdentitySigning())
}

// profileFor maps a content profile name to the protocol's AEAD profile.
//
// Each name corresponds to a row of the per-format encryption matrix in SCHAT.md
// section 5.1; the client picks the row, and the header carries it so the receiver
// knows which one was used.
func profileFor(name string) (protocol.AEADProfile, error) {
	switch name {
	case "text", "":
		return protocol.ProfileText, nil
	case "image":
		return protocol.ProfileImage, nil
	case "video":
		return protocol.ProfileVideo, nil
	case "file":
		return protocol.ProfileFile, nil
	case "voice":
		return protocol.ProfileVoice, nil
	case "header":
		return protocol.ProfileHeader, nil
	case "database":
		return protocol.ProfileDatabase, nil
	default:
		return 0, fmt.Errorf("%w: %q", protocol.ErrUnknownProfile, name)
	}
}

func normaliseHex(value string) string {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

func decodeHexOrNil(value string) []byte {
	if value == "" {
		return nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil
	}
	return raw
}

func short(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16] + "…"
}
