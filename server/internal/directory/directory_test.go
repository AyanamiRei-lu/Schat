package directory

import (
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func hexN(fill byte, n int) string {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = fill
	}
	return hex.EncodeToString(raw)
}

func sampleBundle(identity byte) Bundle {
	return Bundle{
		IdentitySigning:       hexN(identity, 32),
		IdentityAgreement:     hexN(identity+1, 32),
		SignedPreKey:          hexN(identity+2, 32),
		SignedPreKeyID:        1,
		SignedPreKeySignature: hexN(identity+3, 64),
		OneTimePreKeys: []OneTimePreKey{
			{ID: 1, Public: hexN(0x10, 32)},
			{ID: 2, Public: hexN(0x11, 32)},
			{ID: 3, Public: hexN(0x12, 32)},
		},
	}
}

func newTestDirectory(t *testing.T) *Directory {
	t.Helper()
	d, err := New(time.Hour, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestPublishAndFetch(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x20)

	key, err := d.Publish(bundle)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if key != strings.ToLower(bundle.IdentitySigning) {
		t.Fatalf("key is %q, want the lowercased identity", key)
	}

	got, err := d.Fetch(bundle.IdentitySigning)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.IdentitySigning != bundle.IdentitySigning {
		t.Error("identity signing key did not round trip")
	}
	if got.SignedPreKeySignature != bundle.SignedPreKeySignature {
		t.Error("signed prekey signature did not round trip")
	}
}

func TestFetchIsCaseInsensitive(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x30)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if _, err := d.Fetch(strings.ToUpper(bundle.IdentitySigning)); err != nil {
		t.Fatalf("an uppercase lookup key should work: %v", err)
	}
}

func TestFetchUnknownIdentity(t *testing.T) {
	d := newTestDirectory(t)
	if _, err := d.Fetch(hexN(0x99, 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestOneTimePreKeysAreConsumedOnce is the property the whole package exists for.
//
// A one-time prekey handed to two initiators is not one-time, and the forward-secrecy
// argument for the session's first message collapses with it.
func TestOneTimePreKeysAreConsumedOnce(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x40)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	seen := map[int64]bool{}
	for i := 0; i < len(bundle.OneTimePreKeys); i++ {
		got, err := d.Fetch(bundle.IdentitySigning)
		if err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
		if len(got.OneTimePreKeys) != 1 {
			t.Fatalf("Fetch %d returned %d one-time prekeys, want exactly 1",
				i, len(got.OneTimePreKeys))
		}
		id := got.OneTimePreKeys[0].ID
		if seen[id] {
			t.Fatalf("one-time prekey %d was handed out twice", id)
		}
		seen[id] = true
	}

	if len(seen) != len(bundle.OneTimePreKeys) {
		t.Fatalf("consumed %d distinct prekeys, want %d", len(seen), len(bundle.OneTimePreKeys))
	}
}

// TestEmptyPoolDegradesRatherThanFailing covers the documented fallback: no one-time
// prekey means a slightly weaker session, not a broken one.
func TestEmptyPoolDegradesRatherThanFailing(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x50)
	bundle.OneTimePreKeys = nil
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got, err := d.Fetch(bundle.IdentitySigning)
	if err != nil {
		t.Fatalf("a bundle with no one-time prekeys must still be served: %v", err)
	}
	if len(got.OneTimePreKeys) != 0 {
		t.Fatalf("got %d one-time prekeys from an empty pool", len(got.OneTimePreKeys))
	}
}

func TestPoolExhaustionAfterConsumption(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x60)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	for i := 0; i < len(bundle.OneTimePreKeys); i++ {
		if _, err := d.Fetch(bundle.IdentitySigning); err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
	}

	// The pool is now empty; the next fetch must still work, without a prekey.
	got, err := d.Fetch(bundle.IdentitySigning)
	if err != nil {
		t.Fatalf("Fetch after exhaustion: %v", err)
	}
	if len(got.OneTimePreKeys) != 0 {
		t.Fatal("a prekey appeared after the pool was exhausted")
	}
}

// TestFetchDoesNotLeakTheWholePool makes sure a single fetch cannot harvest the pool.
func TestFetchDoesNotLeakTheWholePool(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x70)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got, err := d.Fetch(bundle.IdentitySigning)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.OneTimePreKeys) > 1 {
		t.Fatalf("a fetch returned %d prekeys; the pool leaked", len(got.OneTimePreKeys))
	}
}

func TestRepublishReplacesAndRefillsThePool(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x80)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := d.Fetch(bundle.IdentitySigning); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Republishing is how a client refills; the pool must come back in full.
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("re-Publish: %v", err)
	}

	got, err := d.Fetch(bundle.IdentitySigning)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.OneTimePreKeys) != 1 || got.OneTimePreKeys[0].ID != bundle.OneTimePreKeys[0].ID {
		t.Fatalf("the pool was not refilled: %+v", got.OneTimePreKeys)
	}

	if identities, _, _ := d.Stats(); identities != 1 {
		t.Fatalf("republishing created %d identities, want 1", identities)
	}
}

func TestPublishedPoolIsCopied(t *testing.T) {
	d := newTestDirectory(t)
	bundle := sampleBundle(0x90)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Mutating the caller's slice after publishing must not affect stored state.
	for i := range bundle.OneTimePreKeys {
		bundle.OneTimePreKeys[i].ID = 999
	}

	got, err := d.Fetch(bundle.IdentitySigning)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.OneTimePreKeys[0].ID == 999 {
		t.Fatal("the directory aliased the caller's prekey slice")
	}
}

func TestValidateRejectsBadBundles(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Bundle)
	}{
		{"short identity", func(b *Bundle) { b.IdentitySigning = "aabb" }},
		{"non-hex identity", func(b *Bundle) { b.IdentitySigning = strings.Repeat("zz", 32) }},
		{"short agreement key", func(b *Bundle) { b.IdentityAgreement = hexN(1, 16) }},
		{"short signed prekey", func(b *Bundle) { b.SignedPreKey = hexN(1, 16) }},
		{"short signature", func(b *Bundle) { b.SignedPreKeySignature = hexN(1, 32) }},
		{"bad one-time prekey", func(b *Bundle) {
			b.OneTimePreKeys = []OneTimePreKey{{ID: 1, Public: "short"}}
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := sampleBundle(0xA0)
			c.mutate(&b)
			if err := b.Validate(); !errors.Is(err, ErrBadBundle) {
				t.Fatalf("expected ErrBadBundle, got %v", err)
			}
			if _, err := newTestDirectory(t).Publish(b); err == nil {
				t.Fatal("Publish accepted an invalid bundle")
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	valid := hexN(0xB0, 32)
	if got, err := ParseKey(valid); err != nil || got != valid {
		t.Fatalf("ParseKey(%q) = %q, %v", valid, got, err)
	}
	if got, err := ParseKey(strings.ToUpper(valid)); err != nil || got != valid {
		t.Fatalf("ParseKey should normalise case, got %q, %v", got, err)
	}

	for _, bad := range []string{"", "aabb", "zz", strings.Repeat("aa", 33)} {
		if _, err := ParseKey(bad); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("ParseKey(%q) should fail with ErrInvalidIdentity, got %v", bad, err)
		}
	}
}

func TestExpiry(t *testing.T) {
	d, err := New(time.Minute, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	current := base
	d.now = func() time.Time { return current }

	bundle := sampleBundle(0xC0)
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	current = base.Add(30 * time.Second)
	if _, err := d.Fetch(bundle.IdentitySigning); err != nil {
		t.Fatalf("a fresh bundle must be served: %v", err)
	}

	current = base.Add(2 * time.Minute)
	if _, err := d.Fetch(bundle.IdentitySigning); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected an expired bundle to disappear, got %v", err)
	}
	if identities, _, _ := d.Stats(); identities != 0 {
		t.Fatalf("the expired bundle was not removed from the map: %d identities remain", identities)
	}
}

func TestSweepRemovesExpiredBundles(t *testing.T) {
	d, _ := New(time.Minute, 10)
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	current := base
	d.now = func() time.Time { return current }

	if _, err := d.Publish(sampleBundle(0xD0)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := d.Publish(sampleBundle(0xE0)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	current = base.Add(30 * time.Second)
	if removed := d.Sweep(); removed != 0 {
		t.Fatalf("Sweep removed %d fresh bundles", removed)
	}

	current = base.Add(2 * time.Minute)
	if removed := d.Sweep(); removed != 2 {
		t.Fatalf("Sweep removed %d bundles, want 2", removed)
	}
}

func TestCapacityIsBounded(t *testing.T) {
	d, err := New(time.Hour, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := d.Publish(sampleBundle(0x01)); err != nil {
		t.Fatalf("Publish 1: %v", err)
	}
	if _, err := d.Publish(sampleBundle(0x02)); err != nil {
		t.Fatalf("Publish 2: %v", err)
	}
	if _, err := d.Publish(sampleBundle(0x03)); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}

	// Republishing an existing identity must still work at capacity.
	if _, err := d.Publish(sampleBundle(0x01)); err != nil {
		t.Fatalf("republishing at capacity failed: %v", err)
	}
}

func TestClearRemovesEverything(t *testing.T) {
	d := newTestDirectory(t)
	if _, err := d.Publish(sampleBundle(0xF0)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	d.Clear()

	if identities, prekeys, _ := d.Stats(); identities != 0 || prekeys != 0 {
		t.Fatalf("after Clear: %d identities, %d prekeys", identities, prekeys)
	}
}

func TestNewRejectsBadBounds(t *testing.T) {
	if _, err := New(0, 10); err == nil {
		t.Error("expected an error for a zero TTL")
	}
	if _, err := New(time.Hour, 0); err == nil {
		t.Error("expected an error for zero capacity")
	}
}

// TestConcurrentFetchNeverDuplicatesAPreKey is the race-detector test for the property
// that matters most: under concurrent fetches, no prekey may be handed out twice.
func TestConcurrentFetchNeverDuplicatesAPreKey(t *testing.T) {
	d, err := New(time.Hour, 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const poolSize = 200
	bundle := sampleBundle(0x11)
	bundle.OneTimePreKeys = make([]OneTimePreKey, poolSize)
	for i := range bundle.OneTimePreKeys {
		bundle.OneTimePreKeys[i] = OneTimePreKey{ID: int64(i + 1), Public: hexN(byte(i), 32)}
	}
	if _, err := d.Publish(bundle); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	var (
		mu   sync.Mutex
		seen = map[int64]int{}
		wg   sync.WaitGroup
	)

	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < poolSize; i++ {
				got, err := d.Fetch(bundle.IdentitySigning)
				if err != nil || len(got.OneTimePreKeys) == 0 {
					return
				}
				mu.Lock()
				seen[got.OneTimePreKeys[0].ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	for id, count := range seen {
		if count != 1 {
			t.Fatalf("one-time prekey %d was handed out %d times", id, count)
		}
	}
	if len(seen) != poolSize {
		t.Fatalf("handed out %d distinct prekeys, want %d", len(seen), poolSize)
	}
}
