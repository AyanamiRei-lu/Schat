package protocol

import (
	"testing"
)

// TestDeliveryTokenRotation is the metadata protection property: tokens for
// different days and different ring positions must be unrelated, so that the
// relay server cannot link a user's traffic across days or across contacts.
func TestDeliveryTokenRotation(t *testing.T) {
	routeKey := testKey(0x51)

	day0idx0, err := DeliveryToken(routeKey, 0, 0)
	if err != nil {
		t.Fatalf("DeliveryToken: %v", err)
	}

	// Deterministic: the recipient must be able to compute the same token
	// without any communication.
	repeat, err := DeliveryToken(routeKey, 0, 0)
	if err != nil {
		t.Fatalf("DeliveryToken (repeat): %v", err)
	}
	if day0idx0 != repeat {
		t.Fatal("delivery token derivation is not deterministic")
	}

	// Different ring index: two messages in the same day must not be linkable.
	day0idx1, err := DeliveryToken(routeKey, 0, 1)
	if err != nil {
		t.Fatalf("DeliveryToken(idx 1): %v", err)
	}
	if day0idx0 == day0idx1 {
		t.Fatal("different ring indices produced the same token; same-day messages are linkable")
	}

	// Different epoch: yesterday's token must not work today.
	day1idx0, err := DeliveryToken(routeKey, 1, 0)
	if err != nil {
		t.Fatalf("DeliveryToken(epoch 1): %v", err)
	}
	if day0idx0 == day1idx0 {
		t.Fatal("tokens do not rotate across epochs")
	}

	// Different user: tokens must not collide between users.
	otherKey, err := DeliveryToken(testKey(0x52), 0, 0)
	if err != nil {
		t.Fatalf("DeliveryToken(other key): %v", err)
	}
	if day0idx0 == otherKey {
		t.Fatal("two users derived the same token")
	}
}

func TestDeliveryTokenRejectsBadKey(t *testing.T) {
	if _, err := DeliveryToken(make([]byte, 16), 0, 0); err == nil {
		t.Fatal("expected an error for a 16-byte route key")
	}
	if _, err := DeliveryToken(nil, 0, 0); err == nil {
		t.Fatal("expected an error for an empty route key")
	}
}

func TestEpochFor(t *testing.T) {
	cases := []struct {
		unix int64
		want uint64
	}{
		{0, 0},
		{-5, 0},
		{86399, 0},
		{86400, 1},
		{86401, 1},
		{172800, 2},
	}

	for _, c := range cases {
		if got := EpochFor(c.unix); got != c.want {
			t.Errorf("EpochFor(%d) = %d, want %d", c.unix, got, c.want)
		}
	}
}
