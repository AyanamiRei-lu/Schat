package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func mustEncrypt(t *testing.T, s *Session, msg string) *Envelope {
	t.Helper()
	env, err := s.EncryptMessage([]byte(msg), ProfileText)
	if err != nil {
		t.Fatalf("EncryptMessage(%q): %v", msg, err)
	}
	return env
}

func mustDecrypt(t *testing.T, s *Session, env *Envelope, want string) {
	t.Helper()
	got, err := s.DecryptMessage(env)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(got) != want {
		t.Fatalf("decrypted %q, want %q", got, want)
	}
}

// TestLongBidirectionalConversation is the basic liveness test. It crosses several
// DH ratchet steps in each direction because 60 messages exceeds the maximum
// adaptive threshold of 31, and each side ratchets when it sees the other's new
// key.
func TestLongBidirectionalConversation(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	for i := 0; i < 60; i++ {
		msgA := fmt.Sprintf("A->B #%d", i)
		mustDecrypt(t, b, mustEncrypt(t, a, msgA), msgA)

		msgB := fmt.Sprintf("B->A #%d", i)
		mustDecrypt(t, a, mustEncrypt(t, b, msgB), msgB)
	}
}

// TestOutOfOrderDelivery is what the skipped-key cache exists for. Unreliable
// transport reorders messages; none may be lost.
func TestOutOfOrderDelivery(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	const n = 6
	envs := make([]*Envelope, n)
	for i := 0; i < n; i++ {
		envs[i] = mustEncrypt(t, a, fmt.Sprintf("message %d", i))
	}

	// Deliver in a deliberately scrambled order: 0, 3, 1, 5, 2, 4.
	for _, i := range []int{0, 3, 1, 5, 2, 4} {
		mustDecrypt(t, b, envs[i], fmt.Sprintf("message %d", i))
	}

	// Everything was delivered, so nothing should remain cached.
	if b.SkippedKeyCount() != 0 {
		t.Fatalf("%d skipped keys remain after all messages arrived", b.SkippedKeyCount())
	}
}

// TestLateMessageFromPreviousChain is the regression test for the first defect
// found while building the ratchet.
//
// A message delayed past the peer's next ratchet step carries the OLD ratchet key.
// The obvious implementation asks "has the peer's key changed?" first, sees yes,
// installs a bogus receiving chain and destroys the session. The fix is to consult
// the skipped-key cache before deciding to ratchet.
func TestLateMessageFromPreviousChain(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	// A sends two messages on its first chain; the first is held back.
	stranded := mustEncrypt(t, a, "stranded in the old chain")
	mustDecrypt(t, b, mustEncrypt(t, a, "second"), "second")

	// B replies, which causes A to ratchet to a new sending chain.
	mustDecrypt(t, a, mustEncrypt(t, b, "reply"), "reply")

	// A sends on the new chain, which causes B to ratchet. B's remote ratchet key is
	// now A's new key, so the stranded message looks like it announces yet another
	// ratchet.
	mustDecrypt(t, b, mustEncrypt(t, a, "on the new chain"), "on the new chain")

	// The stranded message belongs to the chain B has already moved past and must
	// come out of the cache rather than triggering a ratchet.
	mustDecrypt(t, b, stranded, "stranded in the old chain")

	// And the session must still be healthy afterwards: a botched ratchet would
	// have poisoned both chains permanently.
	mustDecrypt(t, b, mustEncrypt(t, a, "still alive"), "still alive")
	mustDecrypt(t, a, mustEncrypt(t, b, "still alive too"), "still alive too")
}

// TestRatchetAdvancesOnPeerKey verifies the standard Double Ratchet rule that
// replaced the unsound adaptive threshold.
//
// Each side refreshes its ratchet key in response to the peer's, so every round
// trip gives both directions fresh DH entropy. A one-way burst, by contrast, must
// NOT refresh anything: there is no peer key to ratchet against, and inventing one
// breaks the strict alternation the protocol depends on.
func TestRatchetAdvancesOnPeerKey(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	startA := a.RatchetPublic()
	startB := b.RatchetPublic()

	for i := 0; i < 3; i++ {
		mustDecrypt(t, b, mustEncrypt(t, a, "ping"), "ping")
		mustDecrypt(t, a, mustEncrypt(t, b, "pong"), "pong")
	}

	if bytes.Equal(a.RatchetPublic(), startA) {
		t.Fatal("A's ratchet key never advanced across three round trips")
	}
	if bytes.Equal(b.RatchetPublic(), startB) {
		t.Fatal("B's ratchet key never advanced across three round trips")
	}

	// A one-way burst, by contrast, must NOT refresh the sender's ratchet key: there
	// is no peer key to ratchet against, and manufacturing one would break the
	// strict alternation the protocol depends on.
	//
	// One message is delivered first so that B has caught up with A's latest ratchet
	// key. Without that, B legitimately performs its own pending ratchet on the
	// first burst message, and the assertion below would be measuring the wrong
	// thing.
	mustDecrypt(t, b, mustEncrypt(t, a, "catch up"), "catch up")

	beforeA := a.RatchetPublic()
	beforeB := b.RatchetPublic()
	for i := 0; i < 20; i++ {
		mustDecrypt(t, b, mustEncrypt(t, a, "burst"), "burst")
	}
	if !bytes.Equal(a.RatchetPublic(), beforeA) {
		t.Fatal("a one-way burst refreshed the sender's ratchet key, which the peer could not follow")
	}
	if !bytes.Equal(b.RatchetPublic(), beforeB) {
		t.Fatal("a one-way burst refreshed the receiver's ratchet key")
	}

	// The conversation must still work in both directions afterwards.
	mustDecrypt(t, a, mustEncrypt(t, b, "after burst"), "after burst")
}

// TestReplayIsRejected: the same envelope must never decrypt twice.
func TestReplayIsRejected(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	env := mustEncrypt(t, a, "only once")
	mustDecrypt(t, b, env, "only once")

	if _, err := b.DecryptMessage(env); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay on redelivery, got %v", err)
	}

	// And again, to be sure the first rejection was not a fluke that consumed
	// something.
	if _, err := b.DecryptMessage(env); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay on the second redelivery, got %v", err)
	}

	// A replay of an out-of-order message must also be rejected, which exercises
	// the path where the key came from the skipped cache rather than the chain.
	first := mustEncrypt(t, a, "first")
	second := mustEncrypt(t, a, "second")
	mustDecrypt(t, b, second, "second")
	mustDecrypt(t, b, first, "first")
	if _, err := b.DecryptMessage(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay when replaying a cached-key message, got %v", err)
	}
}

// TestTamperedCiphertextIsRejected: every single-bit change must be caught.
func TestTamperedCiphertextIsRejected(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	env := mustEncrypt(t, a, "authentic message")

	for i := range env.Ciphertext {
		mutated := &Envelope{
			Header:     env.Header,
			Ciphertext: append([]byte(nil), env.Ciphertext...),
		}
		mutated.Ciphertext[i] ^= 0x01

		if _, err := b.DecryptMessage(mutated); err == nil {
			t.Fatalf("flipping bit 0 of ciphertext byte %d was not detected", i)
		}
	}
}

// TestTamperedHeaderIsRejected covers the associated-data binding. The header is
// not encrypted, so an attacker can change it freely — but doing so must break the
// tag.
func TestTamperedHeaderIsRejected(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	env := mustEncrypt(t, a, "header-bound message")

	// A different content profile. Even though this only changes one header byte,
	// the AEAD's associated data changes and the tag must fail.
	swapped := *env
	swapped.Header.Profile = ProfileImage
	if _, err := b.DecryptMessage(&swapped); err == nil {
		t.Fatal("swapping the content profile in transit was not detected")
	}

	// A different ratchet public key.
	other := *env
	other.Header.RatchetPub[0] ^= 0x01
	if _, err := b.DecryptMessage(&other); err == nil {
		t.Fatal("mutating the ratchet public key in transit was not detected")
	}

	// A different version must be refused outright rather than negotiated down.
	badVer := *env
	badVer.Header.Version = 0x02
	if _, err := b.DecryptMessage(&badVer); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("expected ErrUnknownVersion, got %v", err)
	}
}

// TestReflectionIsRejected: a peer must not accept its own ciphertext back. This is
// what the direction byte in the message key derivation buys.
func TestReflectionIsRejected(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	// Exchange first so both sides have receiving chains installed; without this
	// the test would pass trivially because A cannot receive at all yet.
	mustDecrypt(t, b, mustEncrypt(t, a, "warm up A->B"), "warm up A->B")
	mustDecrypt(t, a, mustEncrypt(t, b, "warm up B->A"), "warm up B->A")

	reflected := mustEncrypt(t, a, "bounce me back")
	if _, err := a.DecryptMessage(reflected); err == nil {
		t.Fatal("A accepted its own ciphertext, which a reflection attack requires")
	}
}

// TestCrossSessionReplayIsRejected: an envelope from one session must not decrypt
// in another, even one involving the same identities.
func TestCrossSessionReplayIsRejected(t *testing.T) {
	a1, b1 := newTestSessionPair(t)
	defer a1.Close()
	defer b1.Close()

	a2, b2 := newTestSessionPair(t)
	defer a2.Close()
	defer b2.Close()

	env := mustEncrypt(t, a1, "belongs to session 1")

	if _, err := b2.DecryptMessage(env); err == nil {
		t.Fatal("an envelope from another session decrypted")
	}
	// The intended recipient still works, so the rejection above was not caused by
	// a broken envelope.
	mustDecrypt(t, b1, env, "belongs to session 1")
}

// TestUnrelatedSenderIsRejected covers a forged envelope from a party that never
// participated in the handshake.
func TestUnrelatedSenderIsRejected(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	other, otherPeer := newTestSessionPair(t)
	defer other.Close()
	defer otherPeer.Close()

	env := mustEncrypt(t, other, "not for you")
	if _, err := b.DecryptMessage(env); err == nil {
		t.Fatal("an envelope from an unrelated session decrypted")
	}
}

// TestExcessiveSkipGapIsRejected is the denial-of-service bound: a forged counter
// must be refused before any key derivation work is attempted.
func TestExcessiveSkipGapIsRejected(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	env := mustEncrypt(t, a, "forged counter")
	// Warm the session so b has a receiving chain.
	mustDecrypt(t, b, env, "forged counter")

	forged := mustEncrypt(t, a, "forged counter 2")
	forged.Header.Counter = MaxReceiveGap + 100

	_, err := b.DecryptMessage(forged)
	if !errors.Is(err, ErrTooManySkipped) {
		t.Fatalf("expected ErrTooManySkipped, got %v", err)
	}
}

// TestSkippedCacheIsBounded checks the eviction rule directly. The cache is what
// turns "attacker forges large counters" from an out-of-memory kill into a lost
// message.
func TestSkippedCacheIsBounded(t *testing.T) {
	s := &Session{skipped: make(map[skippedKey]*MessageKey)}

	ratchet := bytes.Repeat([]byte{0x9a}, RatchetPubSize)
	for i := 0; i < MaxSkippedKeys+250; i++ {
		mk := &MessageKey{}
		mk.Key[0] = byte(i)
		s.storeSkippedLocked(ratchet, uint32(i), mk)
	}

	if got := len(s.skipped); got > MaxSkippedKeys {
		t.Fatalf("skipped key cache holds %d entries, over the bound of %d", got, MaxSkippedKeys)
	}
	if got := len(s.skippedOrder); got > MaxSkippedKeys {
		t.Fatalf("eviction order holds %d entries, over the bound of %d", got, MaxSkippedKeys)
	}

	// The most recent entries must be the ones that survived.
	last := s.takeSkippedLocked(ratchet, uint32(MaxSkippedKeys+249))
	if last == nil {
		t.Fatal("the newest skipped key was evicted")
	}
}

// TestEveryProfileRoundTripsThroughASession exercises the whole AEAD matrix over a
// live ratchet rather than in isolation, which is where a profile/nonce-width
// mismatch would actually show up.
func TestEveryProfileRoundTripsThroughASession(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	for _, profile := range AllProfiles() {
		t.Run(profile.String(), func(t *testing.T) {
			want := "payload for " + profile.String()
			env, err := a.EncryptMessage([]byte(want), profile)
			if err != nil {
				t.Fatalf("EncryptMessage: %v", err)
			}
			if env.Header.Profile != profile {
				t.Fatalf("header carries profile %s, want %s", env.Header.Profile, profile)
			}
			got, err := b.DecryptMessage(env)
			if err != nil {
				t.Fatalf("DecryptMessage: %v", err)
			}
			if string(got) != want {
				t.Fatalf("decrypted %q, want %q", got, want)
			}
		})
	}
}

// TestCountersAdvance checks the ratchet bookkeeping that the wire format depends
// on.
func TestCountersAdvance(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	if a.SendCounter() != 0 || a.RecvCounter() != 0 {
		t.Fatalf("fresh session counters are %d/%d, want 0/0", a.SendCounter(), a.RecvCounter())
	}

	for i := 0; i < 3; i++ {
		mustDecrypt(t, b, mustEncrypt(t, a, "x"), "x")
	}

	if a.SendCounter() != 3 {
		t.Errorf("A send counter is %d, want 3", a.SendCounter())
	}
	if b.RecvCounter() != 3 {
		t.Errorf("B receive counter is %d, want 3", b.RecvCounter())
	}
}

// TestSkippedKeysAreConsumedOnce makes sure a cached key cannot be used twice.
func TestSkippedKeysAreConsumedOnce(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	first := mustEncrypt(t, a, "first")
	second := mustEncrypt(t, a, "second")

	// Delivering "second" first caches the key for "first".
	mustDecrypt(t, b, second, "second")
	if b.SkippedKeyCount() != 1 {
		t.Fatalf("expected one cached key, got %d", b.SkippedKeyCount())
	}

	mustDecrypt(t, b, first, "first")
	if b.SkippedKeyCount() != 0 {
		t.Fatalf("the cached key was not consumed: %d remain", b.SkippedKeyCount())
	}
	if _, err := b.DecryptMessage(first); !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay after consuming the cached key, got %v", err)
	}
}

// TestEmptyAndLargePayloads covers the padding boundaries end to end.
func TestEmptyAndLargePayloads(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	payloads := []string{
		"",
		"a",
		string(bytes.Repeat([]byte("x"), 255)),
		string(bytes.Repeat([]byte("y"), 300)),
		string(bytes.Repeat([]byte("z"), 70000)),
	}

	for i, want := range payloads {
		env, err := a.EncryptMessage([]byte(want), ProfileText)
		if err != nil {
			t.Fatalf("payload %d: EncryptMessage: %v", i, err)
		}
		got, err := b.DecryptMessage(env)
		if err != nil {
			t.Fatalf("payload %d: DecryptMessage: %v", i, err)
		}
		if string(got) != want {
			t.Fatalf("payload %d of length %d did not round trip (got length %d)",
				i, len(want), len(got))
		}
	}
}

// TestSessionRejectsBadProfile keeps the fail-closed rule at the session boundary.
func TestSessionRejectsBadProfile(t *testing.T) {
	a, _ := newTestSessionPair(t)
	defer a.Close()

	if _, err := a.EncryptMessage([]byte("x"), AEADProfile(0x7f)); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected ErrUnknownProfile from EncryptMessage, got %v", err)
	}
}

func TestDecryptRejectsNilEnvelope(t *testing.T) {
	a, _ := newTestSessionPair(t)
	defer a.Close()

	if _, err := a.DecryptMessage(nil); err == nil {
		t.Fatal("expected an error for a nil envelope")
	}
}

// TestDecryptRejectsTruncatedCiphertext guards the length check that runs before
// any AEAD call, so a one-byte frame cannot reach the cipher implementation.
func TestDecryptRejectsTruncatedCiphertext(t *testing.T) {
	a, b := newTestSessionPair(t)
	defer a.Close()
	defer b.Close()

	env := mustEncrypt(t, a, "short")
	truncated := &Envelope{Header: env.Header, Ciphertext: env.Ciphertext[:8]}

	if _, err := b.DecryptMessage(truncated); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}
