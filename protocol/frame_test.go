package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func testHeader() Header {
	h := Header{
		Version:      WireVersion,
		Profile:      ProfileText,
		PrevChainLen: 42,
		Counter:      1234,
	}
	for i := range h.RatchetPub {
		h.RatchetPub[i] = byte(i)
	}
	return h
}

func TestHeaderRoundTrip(t *testing.T) {
	in := testHeader()

	wire := in.Marshal()
	if len(wire) != HeaderSize {
		t.Fatalf("marshalled header is %d bytes, want %d", len(wire), HeaderSize)
	}

	out, err := UnmarshalHeader(wire)
	if err != nil {
		t.Fatalf("UnmarshalHeader: %v", err)
	}
	if out.Version != in.Version {
		t.Errorf("version %d, want %d", out.Version, in.Version)
	}
	if out.Flags != in.Flags {
		t.Errorf("flags %d, want %d", out.Flags, in.Flags)
	}
	if out.Profile != in.Profile {
		t.Errorf("profile %s, want %s", out.Profile, in.Profile)
	}
	if out.RatchetPub != in.RatchetPub {
		t.Error("ratchet public key did not survive the round trip")
	}
	if out.PrevChainLen != in.PrevChainLen {
		t.Errorf("prev chain length %d, want %d", out.PrevChainLen, in.PrevChainLen)
	}
	if out.Counter != in.Counter {
		t.Errorf("counter %d, want %d", out.Counter, in.Counter)
	}
}

// TestHeaderFieldOffsets pins the wire layout. The header is a frozen contract
// that both peers and any future independent implementation must agree on byte for
// byte, so the offsets are asserted rather than described.
func TestHeaderFieldOffsets(t *testing.T) {
	h := testHeader()
	h.Profile = ProfileVideo
	wire := h.Marshal()

	// ver(1) flags(1) profile(1) dh(32) pn(4) n(4) == 43
	if wire[0] != WireVersion {
		t.Errorf("byte 0 should be the version, got %d", wire[0])
	}
	if wire[1] != h.Flags {
		t.Errorf("byte 1 should be the flags, got %d", wire[1])
	}
	if wire[2] != byte(ProfileVideo) {
		t.Errorf("byte 2 should be the content profile, got %d", wire[2])
	}
	if !bytes.Equal(wire[3:35], h.RatchetPub[:]) {
		t.Error("bytes 3..35 should be the ratchet public key")
	}
	if wire[35] != 0 || wire[36] != 0 || wire[37] != 0 || wire[38] != 42 {
		t.Errorf("bytes 35..39 should be big-endian prev chain length 42, got %v", wire[35:39])
	}
	// 1234 == 0x000004D2
	if wire[39] != 0x00 || wire[40] != 0x00 || wire[41] != 0x04 || wire[42] != 0xD2 {
		t.Errorf("bytes 39..43 should be big-endian counter 1234, got %v", wire[39:43])
	}
}

// TestHeaderRejectsUnknownVersion proves SCS-1 fails closed rather than
// negotiating down to an older revision.
func TestHeaderRejectsUnknownVersion(t *testing.T) {
	wire := testHeader().Marshal()
	wire[0] = 0x00

	if _, err := UnmarshalHeader(wire); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("expected ErrUnknownVersion, got %v", err)
	}
}

// TestHeaderRejectsUnknownProfile is the fail-closed check for content types: an
// unrecognised profile must not be guessed at.
func TestHeaderRejectsUnknownProfile(t *testing.T) {
	wire := testHeader().Marshal()
	wire[2] = 0x7f

	if _, err := UnmarshalHeader(wire); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected ErrUnknownProfile, got %v", err)
	}
}

func TestHeaderRejectsShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, HeaderSize - 1} {
		if _, err := UnmarshalHeader(make([]byte, n)); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("length %d: expected ErrShortBuffer, got %v", n, err)
		}
	}
}

func TestHeaderAcceptsLongerBuffer(t *testing.T) {
	// A header may be followed by ciphertext in the same buffer; the decoder must
	// read only its own bytes.
	wire := append(testHeader().Marshal(), []byte("trailing ciphertext")...)
	if _, err := UnmarshalHeader(wire); err != nil {
		t.Fatalf("UnmarshalHeader on a longer buffer: %v", err)
	}
}

func TestHeaderFlags(t *testing.T) {
	var h Header
	if h.Has(FlagUnverifiedIdentity) {
		t.Fatal("a zero header reported a flag as set")
	}

	h.SetFlag(FlagUnverifiedIdentity, true)
	if !h.Has(FlagUnverifiedIdentity) {
		t.Fatal("flag was not set")
	}
	// Setting one flag must not disturb another.
	h.SetFlag(FlagGroupMessage, true)
	if !h.Has(FlagUnverifiedIdentity) || !h.Has(FlagGroupMessage) {
		t.Fatal("setting a second flag cleared the first")
	}

	h.SetFlag(FlagUnverifiedIdentity, false)
	if h.Has(FlagUnverifiedIdentity) {
		t.Fatal("flag was not cleared")
	}
	if !h.Has(FlagGroupMessage) {
		t.Fatal("clearing one flag cleared another")
	}
}

func TestFlagBitsAreDistinct(t *testing.T) {
	flags := []byte{
		FlagHasOneTimePreKey,
		FlagUnverifiedIdentity,
		FlagGroupMessage,
		FlagPaddingExtended,
	}
	for i := range flags {
		for j := i + 1; j < len(flags); j++ {
			if flags[i]&flags[j] != 0 {
				t.Fatalf("flag bits %d and %d collide", i, j)
			}
		}
	}
}

// TestAssociatedDataBindsSessionAndHeader covers the two things a ciphertext must
// be nailed to: the session it belongs to, and the header that describes it.
func TestAssociatedDataBindsSessionAndHeader(t *testing.T) {
	h := testHeader()
	ad := AssociatedData([]byte("session-ad"), h)

	if !bytes.Contains(ad, []byte("session-ad")) {
		t.Fatal("session AD is missing from the associated data")
	}
	if !bytes.Contains(ad, h.Marshal()) {
		t.Fatal("the header is missing from the associated data")
	}

	// Changing any header byte must change the associated data, and therefore
	// break the tag.
	for i := 0; i < HeaderSize; i++ {
		mutated := h
		wire := mutated.Marshal()
		wire[i] ^= 0x01
		if _, err := UnmarshalHeader(wire); err != nil {
			continue // an invalid mutation is rejected before it can matter
		}
		other, err := UnmarshalHeader(wire)
		if err != nil {
			continue
		}
		if bytes.Equal(AssociatedData([]byte("session-ad"), other), ad) {
			t.Fatalf("mutating header byte %d did not change the associated data", i)
		}
	}
}
