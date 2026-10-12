package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

// TestAEADProfilesRoundTrip covers every profile in the matrix. A profile that
// cannot round-trip is a profile that will silently corrupt user data.
func TestAEADProfilesRoundTrip(t *testing.T) {
	plaintext := []byte("SCHAT end-to-end encrypted payload")
	aad := []byte("associated data bound to the frame header")

	for _, p := range AllProfiles() {
		t.Run(p.String(), func(t *testing.T) {
			key := testKey(byte(p))
			nonce := bytes.Repeat([]byte{0x5a}, p.NonceSize())

			ct, err := p.Seal(key, nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if len(ct) != len(plaintext)+p.Overhead() {
				t.Fatalf("ciphertext is %d bytes, want %d",
					len(ct), len(plaintext)+p.Overhead())
			}
			if bytes.Contains(ct, plaintext) {
				t.Fatal("plaintext is visible inside the ciphertext")
			}

			got, err := p.Open(key, nonce, ct, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip mismatch: got %q", got)
			}
		})
	}
}

// TestAEADDetectsTampering is the integrity half of authenticated encryption.
func TestAEADDetectsTampering(t *testing.T) {
	plaintext := []byte("tamper me")
	aad := []byte("aad")

	for _, p := range AllProfiles() {
		t.Run(p.String(), func(t *testing.T) {
			key := testKey(byte(p))
			nonce := bytes.Repeat([]byte{0x11}, p.NonceSize())

			ct, err := p.Seal(key, nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}

			// Flip one bit in every position in turn: not one may go unnoticed.
			for i := range ct {
				mutated := append([]byte(nil), ct...)
				mutated[i] ^= 0x01
				if _, err := p.Open(key, nonce, mutated, aad); err == nil {
					t.Fatalf("flipping bit 0 of byte %d was not detected", i)
				}
			}
		})
	}
}

func TestAEADDetectsWrongKey(t *testing.T) {
	plaintext := []byte("secret")

	for _, p := range AllProfiles() {
		t.Run(p.String(), func(t *testing.T) {
			n := p.NonceSize()
			nonce := bytes.Repeat([]byte{0x22}, n)
			ct, err := p.Seal(testKey(0x01), nonce, plaintext, nil)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if _, err := p.Open(testKey(0x02), nonce, ct, nil); err == nil {
				t.Fatal("decryption succeeded with the wrong key")
			}
		})
	}
}

// TestAEADBindsAssociatedData proves the header is authenticated: an attacker
// who rewrites the ratchet counter or public key in transit must break decryption.
func TestAEADBindsAssociatedData(t *testing.T) {
	p := ProfileText
	key := testKey(0x07)
	nonce := bytes.Repeat([]byte{0x33}, p.NonceSize())
	plaintext := []byte("bound to its header")

	ct, err := p.Seal(key, nonce, plaintext, []byte("header-v1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := p.Open(key, nonce, ct, []byte("header-v2")); err == nil {
		t.Fatal("decryption succeeded after the associated data changed")
	}
}

func TestAEADRejectsWrongKeySize(t *testing.T) {
	for _, p := range AllProfiles() {
		t.Run(p.String(), func(t *testing.T) {
			if _, err := p.NewAEAD(make([]byte, 16)); !errors.Is(err, ErrBadKeySize) {
				t.Fatalf("expected ErrBadKeySize for a 16-byte key, got %v", err)
			}
		})
	}
}

func TestAEADRejectsWrongNonceSize(t *testing.T) {
	p := ProfileText
	key := testKey(0x09)

	short := make([]byte, p.NonceSize()-1)
	if _, err := p.Seal(key, short, []byte("x"), nil); err == nil {
		t.Fatal("expected an error for a short nonce")
	}
}

func TestUnknownProfileIsRejected(t *testing.T) {
	bogus := AEADProfile(0x7f)
	if bogus.Valid() {
		t.Fatal("bogus profile reported as valid")
	}
	if _, err := bogus.NewAEAD(testKey(0x01)); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected ErrUnknownProfile, got %v", err)
	}
	if _, err := bogus.Seal(testKey(0x01), make([]byte, NonceSize), []byte("x"), nil); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected ErrUnknownProfile from Seal, got %v", err)
	}
}

// TestProfileMatrixMatchesSpec pins the per-format choices from SCHAT.md
// section 5.1 so that a future edit cannot quietly swap an algorithm.
func TestProfileMatrixMatchesSpec(t *testing.T) {
	cases := []struct {
		profile   AEADProfile
		wantName  string
		wantNonce int
		wantChunk int
	}{
		{ProfileText, "text/chacha20-poly1305", 12, FileChunkSize},
		{ProfileImage, "image/chacha20-poly1305", 12, ImageChunkSize},
		{ProfileVideo, "video/chacha20-poly1305", 12, VideoChunkSize},
		{ProfileFile, "file/xchacha20-poly1305", 24, FileChunkSize},
		{ProfileVoice, "voice/chacha20-poly1305", 12, VoiceFrameSize},
		{ProfileHeader, "header/aes-256-gcm", 12, FileChunkSize},
		{ProfileDatabase, "database/aes-256-gcm", 12, DBPageSize},
	}

	for _, c := range cases {
		if got := c.profile.String(); got != c.wantName {
			t.Errorf("profile %d: name %q, want %q", c.profile, got, c.wantName)
		}
		if got := c.profile.NonceSize(); got != c.wantNonce {
			t.Errorf("profile %s: nonce %d, want %d", c.wantName, got, c.wantNonce)
		}
		if got := ChunkSizeFor(c.profile); got != c.wantChunk {
			t.Errorf("profile %s: chunk %d, want %d", c.wantName, got, c.wantChunk)
		}
	}
}
