package protocol

import (
	"bytes"
	"testing"
)

// fastParams keeps the test suite quick. Production uses Argon2Balanced
// (64 MiB); the point of the test is the composition around Argon2id, not
// Argon2id itself, which is already covered by its own upstream vectors.
var fastParams = Argon2Params{Memory: 8, Time: 1, Parallelism: 1}

func TestArgon2ParamsValidate(t *testing.T) {
	if err := Argon2Low.Validate(); err != nil {
		t.Errorf("Argon2Low should be valid: %v", err)
	}
	if err := Argon2Balanced.Validate(); err != nil {
		t.Errorf("Argon2Balanced should be valid: %v", err)
	}
	if err := Argon2High.Validate(); err != nil {
		t.Errorf("Argon2High should be valid: %v", err)
	}

	// Argon2 requires memory >= 8 * parallelism. Catching that here turns a
	// library panic into a returned error.
	if err := (Argon2Params{Memory: 8, Time: 1, Parallelism: 2}).Validate(); err == nil {
		t.Error("expected an error when memory is below 8*parallelism")
	}
	if err := (Argon2Params{Memory: 1024, Time: 1, Parallelism: 0}).Validate(); err == nil {
		t.Error("expected an error for zero parallelism")
	}
	if err := (Argon2Params{Memory: 1024, Time: 0, Parallelism: 1}).Validate(); err == nil {
		t.Error("expected an error for zero time cost")
	}
}

// TestArgon2ProfilesWiden is a guard against someone quietly lowering the
// memory cost to make builds faster. Memory hardness IS the security here.
func TestArgon2ProfilesWiden(t *testing.T) {
	if Argon2Low.Memory < 32*1024 {
		t.Fatalf("the lowest Argon2 profile dropped below 32 MiB (%d KiB)", Argon2Low.Memory)
	}
	if Argon2Balanced.Memory <= Argon2Low.Memory {
		t.Fatal("the balanced profile must cost more memory than the low profile")
	}
	if Argon2High.Memory <= Argon2Balanced.Memory {
		t.Fatal("the high profile must cost more memory than the balanced profile")
	}
}

func TestDeriveVaultMaterial(t *testing.T) {
	pass := []byte("correct horse battery staple")
	salt := bytes.Repeat([]byte{0x77}, 32)

	got, err := DeriveVaultMaterial(pass, salt, fastParams)
	if err != nil {
		t.Fatalf("DeriveVaultMaterial: %v", err)
	}
	if len(got) != vaultMaterialSize {
		t.Fatalf("material is %d bytes, want %d", len(got), vaultMaterialSize)
	}

	again, err := DeriveVaultMaterial(pass, salt, fastParams)
	if err != nil {
		t.Fatalf("DeriveVaultMaterial (repeat): %v", err)
	}
	if !bytes.Equal(got, again) {
		t.Fatal("Argon2id derivation is not deterministic")
	}

	// A different salt must give a different result, otherwise rainbow tables
	// would transfer between vaults.
	otherSalt := bytes.Repeat([]byte{0x78}, 32)
	other, err := DeriveVaultMaterial(pass, otherSalt, fastParams)
	if err != nil {
		t.Fatalf("DeriveVaultMaterial (other salt): %v", err)
	}
	if bytes.Equal(got, other) {
		t.Fatal("changing the salt did not change the derived material")
	}

	// A different passphrase must give a different result.
	different, err := DeriveVaultMaterial([]byte("wrong passphrase"), salt, fastParams)
	if err != nil {
		t.Fatalf("DeriveVaultMaterial (other passphrase): %v", err)
	}
	if bytes.Equal(got, different) {
		t.Fatal("changing the passphrase did not change the derived material")
	}
}

func TestDeriveVaultMaterialRejectsBadInput(t *testing.T) {
	short := bytes.Repeat([]byte{0x01}, 8)

	if _, err := DeriveVaultMaterial([]byte("pw"), short, fastParams); err == nil {
		t.Error("expected an error for a salt shorter than 16 bytes")
	}
	if _, err := DeriveVaultMaterial(nil, bytes.Repeat([]byte{1}, 32), fastParams); err == nil {
		t.Error("expected an error for an empty passphrase")
	}
	if _, err := DeriveVaultMaterial([]byte("pw"), bytes.Repeat([]byte{1}, 32),
		Argon2Params{Memory: 4, Time: 1, Parallelism: 2}); err == nil {
		t.Error("expected an error for invalid Argon2 parameters")
	}
}

// TestDeriveVaultKeyRequiresDeviceKey is the second-factor test. A vault key
// must be unobtainable from the passphrase alone, because that is what stops an
// attacker who exfiltrates the database file from a device they cannot unlock.
func TestDeriveVaultKeyRequiresDeviceKey(t *testing.T) {
	material, err := DeriveVaultMaterial([]byte("passphrase"), bytes.Repeat([]byte{0x11}, 32), fastParams)
	if err != nil {
		t.Fatalf("DeriveVaultMaterial: %v", err)
	}
	defer Zero(material)

	deviceKey := testKey(0x41)
	salt := bytes.Repeat([]byte{0x22}, 32)

	vk, err := DeriveVaultKey(material, deviceKey, salt)
	if err != nil {
		t.Fatalf("DeriveVaultKey: %v", err)
	}
	if len(vk) != VaultKeySize {
		t.Fatalf("vault key is %d bytes, want %d", len(vk), VaultKeySize)
	}

	again, err := DeriveVaultKey(material, deviceKey, salt)
	if err != nil {
		t.Fatalf("DeriveVaultKey (repeat): %v", err)
	}
	if !bytes.Equal(vk, again) {
		t.Fatal("vault key derivation is not deterministic")
	}

	// A different device key must give a different vault key: without the
	// hardware key, the passphrase alone is useless.
	other, err := DeriveVaultKey(material, testKey(0x42), salt)
	if err != nil {
		t.Fatalf("DeriveVaultKey (other device): %v", err)
	}
	if bytes.Equal(vk, other) {
		t.Fatal("the device key did not affect the vault key")
	}
}

func TestDeriveVaultKeyRejectsMissingInputs(t *testing.T) {
	material := bytes.Repeat([]byte{0x01}, vaultMaterialSize)
	salt := bytes.Repeat([]byte{0x02}, 32)

	// This must be a hard error rather than a silent downgrade to
	// single-factor protection.
	if _, err := DeriveVaultKey(material, nil, salt); err == nil {
		t.Error("expected an error for a missing device key")
	}
	if _, err := DeriveVaultKey(material, make([]byte, 16), salt); err == nil {
		t.Error("expected an error for a short device key")
	}
	if _, err := DeriveVaultKey(make([]byte, 8), testKey(0x01), salt); err == nil {
		t.Error("expected an error for short vault material")
	}
	if _, err := DeriveVaultKey(material, testKey(0x01), []byte("short")); err == nil {
		t.Error("expected an error for a short vault salt")
	}
}
