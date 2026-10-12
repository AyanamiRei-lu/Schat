package protocol

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Local vault key derivation (SCHAT.md section 4.8).
//
// The server stores nothing, so the device is the only copy of the user's data.
// That makes local protection the highest-value target in the system, and SCS-1
// protects it with two independent factors that must BOTH be present:
//
//	MK_vault = HKDF-SHA256(ikm = Argon2id(passphrase, salt) || deviceKey,
//	                       salt = vaultSalt, info = LabelVault, len = 64)
//
//   - Argon2id makes each offline guess of the passphrase cost both time and
//     memory, which is what defeats GPU and ASIC cracking.
//   - The device key lives in the Android Keystore, ideally in StrongBox
//     hardware, and is non-exportable. An attacker who exfiltrates the database
//     file and even learns the passphrase still cannot decrypt it without the
//     physical device.
//
// The output is split into a 32-byte database key and a 32-byte MAC key.

// Argon2Params configures the memory-hard password hash.
//
// Memory is the security parameter that matters. Lowering it to save RAM
// multiplies a GPU attacker's throughput, so SCS-1 does not go below 32 MiB.
// The cost is paid once per unlock and released immediately afterwards, never
// during routine message handling.
type Argon2Params struct {
	// Memory is the memory cost in KiB.
	Memory uint32

	// Time is the number of passes.
	Time uint32

	// Parallelism is the number of lanes.
	Parallelism uint8
}

// The three published Argon2id profiles from SCHAT.md section 4.8.
var (
	// Argon2Low targets entry-level devices: 32 MiB, ~0.25 s.
	Argon2Low = Argon2Params{Memory: 32 * 1024, Time: 2, Parallelism: 1}

	// Argon2Balanced is the default: 64 MiB, ~0.5 s on a mid-range phone.
	Argon2Balanced = Argon2Params{Memory: 64 * 1024, Time: 3, Parallelism: 2}

	// Argon2High targets flagship devices and high-value data: 256 MiB, ~2 s.
	Argon2High = Argon2Params{Memory: 256 * 1024, Time: 4, Parallelism: 4}
)

// vaultMaterialSize is the Argon2id output length before it is mixed with the
// device key.
const vaultMaterialSize = 64

// VaultKeySize is the total length of the derived vault key material: a
// 32-byte cipher key followed by a 32-byte MAC key.
const VaultKeySize = 64

// Validate checks the parameters against Argon2's own constraints so that a bad
// profile produces an error instead of a panic inside the library.
func (p Argon2Params) Validate() error {
	if p.Parallelism == 0 {
		return fmt.Errorf("scs1: argon2 parallelism must be at least 1")
	}
	if p.Memory < 8*uint32(p.Parallelism) {
		return fmt.Errorf("scs1: argon2 memory %d KiB is below the minimum %d KiB for %d lanes",
			p.Memory, 8*uint32(p.Parallelism), p.Parallelism)
	}
	if p.Time == 0 {
		return fmt.Errorf("scs1: argon2 time cost must be at least 1")
	}
	return nil
}

// DeriveVaultMaterial runs Argon2id over the user passphrase.
//
// The salt must be at least 16 random bytes, generated once per vault and stored
// alongside it (a salt is not a secret, but it must never be reused across
// vaults).
func DeriveVaultMaterial(passphrase, salt []byte, p Argon2Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("%w: argon2 salt must be at least 16 bytes, got %d",
			ErrShortBuffer, len(salt))
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("scs1: passphrase must not be empty")
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Parallelism, vaultMaterialSize), nil
}

// DeriveVaultKey combines the Argon2id output with the hardware-bound device
// key to produce the final vault key.
//
// deviceKey must come from the Android Keystore and must be non-exportable.
// Passing a nil or empty device key is rejected outright rather than silently
// degrading to single-factor protection: a caller that forgets the device key
// should fail loudly, not quietly ship a weaker vault.
func DeriveVaultKey(vaultMaterial, deviceKey, vaultSalt []byte) ([]byte, error) {
	if len(deviceKey) != KeySize {
		return nil, fmt.Errorf("%w: device key must be %d bytes, got %d",
			ErrBadKeySize, KeySize, len(deviceKey))
	}
	if len(vaultMaterial) != vaultMaterialSize {
		return nil, fmt.Errorf("%w: vault material must be %d bytes, got %d",
			ErrBadKeySize, vaultMaterialSize, len(vaultMaterial))
	}
	if len(vaultSalt) < 16 {
		return nil, fmt.Errorf("%w: vault salt must be at least 16 bytes, got %d",
			ErrShortBuffer, len(vaultSalt))
	}

	ikm := make([]byte, 0, len(vaultMaterial)+len(deviceKey))
	ikm = append(ikm, vaultMaterial...)
	ikm = append(ikm, deviceKey...)
	defer Zero(ikm)

	return DeriveLabeled(ikm, LabelVault, vaultSalt, VaultKeySize)
}
