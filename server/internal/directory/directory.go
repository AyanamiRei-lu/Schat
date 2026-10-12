// Package directory publishes and serves public prekey bundles.
//
// # Why the relay needs this
//
// SCS-HSK (SCHAT.md section 4.4) starts with the initiator fetching the responder's
// prekey bundle: an identity key, a signed prekey, and one one-time prekey. The relay
// is the only party both peers can reach before they share a session, so it has to
// hold that material.
//
// # What this package stores, and what it does not
//
// ONLY PUBLIC VALUES. Every field in a bundle is meant to be published; none of it is
// secret, and none of it lets the relay read anything. A bundle contains no message,
// no contact list and no name — just a lookup key and a handful of public keys.
//
// The lookup key is the owner's identity signing public key in hex. That is a real,
// documented trade-off: the relay can see that *some* identity published or fetched a
// bundle, which is metadata about participation in the network. It cannot see who is
// talking to whom, because fetching a bundle is not the same as sending a message, and
// message delivery uses rotating tokens (section 4.7). Closing even that gap needs a
// private information retrieval scheme and is out of scope.
//
// # The one-time prekey must be consumed atomically
//
// A one-time prekey that two initiators both receive is not one-time, and the entire
// forward-secrecy argument for the session's first message collapses. Get therefore
// removes the prekey it hands out, under the same lock that reads it.
package directory

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// IdentityKeySize is the length of an identity signing public key in bytes.
	IdentityKeySize = 32

	// MaxBundleBytes bounds a published bundle. A full pool of 200 prekeys is about
	// 15 KiB, so this leaves generous room while keeping one publisher from consuming
	// the whole budget.
	MaxBundleBytes = 64 << 10

	// MaxKeyPackageBytes bounds the MLS KeyPackage a client may publish. A KeyPackage is a leaf
	// node, a signature and a few extensions — a few hundred bytes in practice — so this is
	// generous. It exists because the field is unauthenticated like the rest of the bundle: a
	// bound is the only thing standing between a hostile publisher and the relay's memory.
	MaxKeyPackageBytes = 4 << 10

	// DefaultTTL is how long a published bundle is served before it is dropped.
	//
	// An expired bundle is not a failure: the owner re-publishes on next launch, and a
	// peer that cannot find one is told so plainly rather than handed something stale.
	DefaultTTL = 30 * 24 * time.Hour

	// DefaultMaxIdentities bounds how many identities the directory will hold.
	DefaultMaxIdentities = 10000
)

// Errors returned by the directory.
var (
	// ErrNotFound means no bundle is published for that identity.
	ErrNotFound = errors.New("directory: no bundle published for that identity")

	// ErrInvalidIdentity means the lookup key is not a valid identity key.
	ErrInvalidIdentity = errors.New("directory: invalid identity key")

	// ErrTooLarge means the published bundle exceeds MaxBundleBytes.
	ErrTooLarge = errors.New("directory: bundle exceeds the size limit")

	// ErrFull means the directory is at capacity.
	ErrFull = errors.New("directory: at capacity")

	// ErrBadBundle means the bundle is missing a required public key.
	ErrBadBundle = errors.New("directory: bundle is missing a required field")
)

// OneTimePreKey is one single-use prekey from an owner's pool.
type OneTimePreKey struct {
	// ID identifies the prekey so the initiator can name it in the handshake.
	ID int64 `json:"id"`

	// Public is the X25519 public value, hex.
	Public string `json:"public"`
}

// Bundle is everything a peer needs to open a session with the owner.
type Bundle struct {
	IdentitySigning       string `json:"identity_signing"`
	IdentityAgreement     string `json:"identity_agreement"`
	SignedPreKey          string `json:"signed_pre_key"`
	SignedPreKeyID        int64  `json:"signed_pre_key_id"`
	SignedPreKeySignature string `json:"signed_pre_key_signature"`

	// OneTimePreKeys is the pool the owner published. A client consuming a bundle
	// receives at most one of these, and it is removed as it is handed over. The
	// field is accepted on publish and never echoed back verbatim.
	OneTimePreKeys []OneTimePreKey `json:"one_time_pre_keys,omitempty"`

	// KeyPackage carries the publisher's MLS KeyPackage, hex-encoded, so that another member can
	// add it to a group without an out-of-band exchange. It is opaque here on purpose: the relay
	// does not parse MLS structures, does not hold keys and cannot read anything, and a field it
	// understood would be the first exception to that.
	//
	// It is optional. A client that only does one-to-one sessions never publishes one, and a
	// client that does must still work with a peer that has not.
	KeyPackage string `json:"key_package,omitempty"`
}

// Validate checks that a published bundle carries the fields a handshake needs.
//
// The signature is NOT verified here. This package has no business holding keys, and
// verification belongs to the initiator, which is the party that must not be fooled
// (protocol.EstablishSession verifies it).
func (b Bundle) Validate() error {
	check := func(name, value string, size int) error {
		raw, err := hex.DecodeString(value)
		if err != nil {
			return fmt.Errorf("%w: %s is not valid hex", ErrBadBundle, name)
		}
		if len(raw) != size {
			return fmt.Errorf("%w: %s must be %d bytes, got %d", ErrBadBundle, name, size, len(raw))
		}
		return nil
	}

	if err := check("identity_signing", b.IdentitySigning, 32); err != nil {
		return err
	}
	if err := check("identity_agreement", b.IdentityAgreement, 32); err != nil {
		return err
	}
	if err := check("signed_pre_key", b.SignedPreKey, 32); err != nil {
		return err
	}
	if err := check("signed_pre_key_signature", b.SignedPreKeySignature, 64); err != nil {
		return err
	}

	for i, otp := range b.OneTimePreKeys {
		raw, err := hex.DecodeString(otp.Public)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("%w: one-time prekey %d is not a 32-byte hex value", ErrBadBundle, i)
		}
	}

	// The KeyPackage is checked for being hex and for fitting the bound, and for nothing else.
	// Its contents are the client's business: validating an MLS structure here would mean the
	// relay understanding MLS, which is exactly what it must not do. A malformed KeyPackage is
	// rejected by the member that tries to ADD its owner, which is the party that can actually
	// tell a bad one from a good one.
	if b.KeyPackage != "" {
		raw, err := hex.DecodeString(b.KeyPackage)
		if err != nil {
			return fmt.Errorf("%w: key_package is not valid hex", ErrBadBundle)
		}
		if len(raw) == 0 {
			return fmt.Errorf("%w: key_package is empty", ErrBadBundle)
		}
		if len(raw) > MaxKeyPackageBytes {
			return fmt.Errorf("%w: key_package is %d bytes, over the %d-byte bound",
				ErrBadBundle, len(raw), MaxKeyPackageBytes)
		}
	}

	return nil
}

// # Publishing is unauthenticated, and that is by design
//
// There are no accounts to authenticate against, so anybody may publish a bundle under
// any identity key — including overwriting somebody else's. The relay cannot prevent
// it, and pretending otherwise by adding a server-side check would only add a false
// sense of protection.
//
// What actually defends against it is on the CLIENT, and is not optional:
//
//  1. A fetcher MUST confirm that the bundle's identity_signing equals the key it asked
//     for. Otherwise an attacker who overwrote the entry could substitute their own
//     identity and have it verify.
//  2. The fetcher verifies the signed prekey signature (protocol.EstablishSession does
//     this), so the bundle must be internally consistent with its own identity.
//  3. The 60-digit safety number is compared out of band, which is what ultimately
//     rules out a substituted identity.
//
// The first check is the one this package's design makes easy to forget, which is why
// it is written down here.

// KeyFor returns the directory lookup key for an identity signing public key.
//
// It is the hex identity itself, lowercased. Using the identity rather than a random
// handle means a peer that already knows who it wants to talk to can find them without
// a separate exchange.
func KeyFor(identitySigningHex string) string {
	return strings.ToLower(strings.TrimSpace(identitySigningHex))
}

// ParseKey validates a lookup key and returns it normalised.
func ParseKey(raw string) (string, error) {
	key := KeyFor(raw)
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("%w: not valid hex", ErrInvalidIdentity)
	}
	if len(decoded) != IdentityKeySize {
		return "", fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidIdentity, IdentityKeySize, len(decoded))
	}
	return key, nil
}

// entry is one stored bundle plus its bookkeeping.
type entry struct {
	bundle    Bundle
	pool      []OneTimePreKey
	published time.Time
}

// Directory is a bounded, in-memory prekey directory.
//
// Nothing is written to disk, for the same reason nothing else is: a restart is
// supposed to lose everything the relay was holding.
type Directory struct {
	mu sync.Mutex

	entries map[string]*entry
	ttl     time.Duration
	max     int

	now func() time.Time

	// dropped counts bundles removed by expiry or eviction, for metrics.
	dropped int64
}

// New creates a directory.
func New(ttl time.Duration, maxIdentities int) (*Directory, error) {
	if ttl <= 0 {
		return nil, errors.New("directory: ttl must be positive")
	}
	if maxIdentities <= 0 {
		return nil, errors.New("directory: max identities must be positive")
	}
	return &Directory{
		entries: make(map[string]*entry, maxIdentities),
		ttl:     ttl,
		max:     maxIdentities,
		now:     time.Now,
	}, nil
}

// Publish stores or replaces the bundle for an identity.
//
// Replacement is deliberate: a client that regenerates its signed prekey or refills its
// one-time pool republishes, and the newest bundle is the correct one.
func (d *Directory) Publish(bundle Bundle) (string, error) {
	if err := bundle.Validate(); err != nil {
		return "", err
	}

	key, err := ParseKey(bundle.IdentitySigning)
	if err != nil {
		return "", err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.entries[key]; !exists && len(d.entries) >= d.max {
		return "", ErrFull
	}

	// Copy the pool so the caller cannot mutate stored state afterwards.
	pool := make([]OneTimePreKey, len(bundle.OneTimePreKeys))
	copy(pool, bundle.OneTimePreKeys)

	d.entries[key] = &entry{
		bundle:    bundle,
		pool:      pool,
		published: d.now(),
	}
	return key, nil
}

// Fetch returns the bundle for an identity, consuming one one-time prekey.
//
// The returned bundle never carries more than one one-time prekey, and the one it
// carries is removed from the pool before this function returns. That is the whole
// point: two initiators asking at the same moment must receive different prekeys, or
// the prekey was never one-time.
//
// When the pool is empty the bundle is returned without a one-time prekey. That is the
// documented degraded mode from SCHAT.md section 4.4, not an error: the session still
// works, it just loses forward secrecy for its first message, and the initiator sees
// the flag that says so.
func (d *Directory) Fetch(identitySigningHex string) (Bundle, error) {
	key, err := ParseKey(identitySigningHex)
	if err != nil {
		return Bundle{}, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	e, ok := d.entries[key]
	if !ok {
		return Bundle{}, ErrNotFound
	}
	if d.now().Sub(e.published) > d.ttl {
		delete(d.entries, key)
		d.dropped++
		return Bundle{}, ErrNotFound
	}

	out := e.bundle
	out.OneTimePreKeys = nil

	if len(e.pool) > 0 {
		out.OneTimePreKeys = []OneTimePreKey{e.pool[0]}
		e.pool = e.pool[1:]
	}
	return out, nil
}

// Stats reports the current occupancy.
func (d *Directory) Stats() (identities int, oneTimePreKeys int, dropped int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, e := range d.entries {
		oneTimePreKeys += len(e.pool)
	}
	return len(d.entries), oneTimePreKeys, d.dropped
}

// Sweep removes expired bundles.
func (d *Directory) Sweep() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := d.now().Add(-d.ttl)
	removed := 0
	for key, e := range d.entries {
		if e.published.Before(cutoff) {
			delete(d.entries, key)
			removed++
		}
	}
	d.dropped += int64(removed)
	return removed
}

// Clear discards everything.
func (d *Directory) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for key := range d.entries {
		delete(d.entries, key)
	}
}
