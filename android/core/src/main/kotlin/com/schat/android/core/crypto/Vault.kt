package com.schat.android.core.crypto

/**
 * Derives key material from the SCS-1 protocol core.
 *
 * It is an interface rather than a direct call into the gomobile binding so that the
 * logic that *uses* derived keys can be unit tested on the JVM, where the Go shared
 * library is neither present nor loadable. The Android implementation is a thin
 * delegate; everything worth testing lives on this side of the boundary.
 */
interface KeyDeriver {
    /** Returns 32 fresh random bytes as hex, for use as a vault salt. */
    fun newSalt(): String

    /** Returns 32 fresh random bytes as hex, for use as a delivery route key. */
    fun newRouteKey(): String

    /**
     * Derives the 64-byte vault key from the user passphrase, the vault salt and the
     * hardware-bound device key.
     *
     * @param profile one of [VaultProfile.LOW], [VaultProfile.BALANCED] or
     *   [VaultProfile.HIGH].
     */
    fun deriveVaultKey(passphrase: String, saltHex: String, deviceKeyHex: String, profile: String): String
}

/** The Argon2id cost profiles, mirroring protocol/vault.go. */
object VaultProfile {
    /** 32 MiB, roughly 0.25 s. Entry-level devices. */
    const val LOW = "low"

    /** 64 MiB, roughly 0.5 s. The default. */
    const val BALANCED = "balanced"

    /** 256 MiB, roughly 2 s. Flagship devices and high-value data. */
    const val HIGH = "high"
}

/**
 * Supplies the hardware-bound half of the vault key.
 *
 * The Android implementation lives in :app, because reaching the Keystore requires
 * Android APIs. Keeping only the contract here is what lets [Vault] be tested
 * against a fake.
 */
interface DeviceKeyProvider {
    /**
     * Returns the 32-byte device key as lowercase hex.
     *
     * Implementations must bind this to hardware; see the implementation in :app for
     * how that is achieved given that Keystore keys cannot be read out.
     */
    fun deviceKeyHex(): String

    /** True when the key is backed by a dedicated security chip. */
    fun isHardwareBacked(): Boolean
}

/**
 * The two halves of a derived vault key.
 *
 * They are separate values because they are used for different purposes — one
 * encrypts, one authenticates — so a leak of one does not weaken the other.
 */
class VaultKey(
    /** 32 bytes for AES-256-GCM. */
    val cipherKey: ByteArray,
    /** 32 bytes reserved for value authentication. */
    val macKey: ByteArray,
) {
    init {
        require(cipherKey.size == 32) { "cipher key must be 32 bytes, got ${cipherKey.size}" }
        require(macKey.size == 32) { "mac key must be 32 bytes, got ${macKey.size}" }
    }

    /**
     * Overwrites both keys.
     *
     * Called once the keys have been handed to the store, so that they do not sit in
     * the heap for the lifetime of the process.
     */
    fun destroy() {
        cipherKey.fill(0)
        macKey.fill(0)
    }
}

/**
 * Derives and holds the vault key.
 *
 * The construction is two-factor by design: the passphrase contributes through
 * Argon2id, and the device key contributes through the Keystore. Both arrive at the
 * protocol core, which mixes them and never returns anything that would let either
 * factor be recovered from the other. Requiring both is what makes a stolen database
 * file useless without the physical phone (SCHAT.md section 4.8).
 */
class Vault(
    private val deriver: KeyDeriver,
    private val minPassphraseLength: Int = MIN_PASSPHRASE_LENGTH,
) {
    /** The result of creating a new vault: the salt to store, and the key to use. */
    data class Created(val saltHex: String, val key: VaultKey)

    /** Creates a new vault: fresh salt, freshly derived key. */
    fun create(passphrase: String, deviceKeyHex: String, profile: String = VaultProfile.BALANCED): Created {
        requirePassphrase(passphrase)
        val salt = deriver.newSalt()
        return Created(salt, derive(passphrase, salt, deviceKeyHex, profile))
    }

    /**
     * Re-derives the key for an existing vault.
     *
     * On failure this returns null rather than throwing: a wrong passphrase is an
     * ordinary event the UI has to handle, not an exceptional condition. Note that
     * Argon2id output cannot be recognised as "wrong" on its own — a bad passphrase
     * simply produces a different key, and the store's authentication tag is what
     * ultimately rejects it.
     */
    fun unlock(
        passphrase: String,
        saltHex: String,
        deviceKeyHex: String,
        profile: String = VaultProfile.BALANCED,
    ): VaultKey? {
        if (passphrase.length < minPassphraseLength) return null
        if (saltHex.isEmpty() || deviceKeyHex.isEmpty()) return null

        return try {
            derive(passphrase, saltHex, deviceKeyHex, profile)
        } catch (e: Exception) {
            null
        }
    }

    private fun derive(passphrase: String, saltHex: String, deviceKeyHex: String, profile: String): VaultKey {
        val hex = deriver.deriveVaultKey(passphrase, saltHex, deviceKeyHex, profile)
        val raw = hexToBytes(hex)
        // A core that returned the wrong size is a bug, not a wrong passphrase, so
        // this fails loudly rather than truncating to something plausible.
        check(raw.size == 64) { "protocol core returned ${raw.size} key bytes, expected 64" }

        val cipherKey = raw.copyOfRange(0, 32)
        val macKey = raw.copyOfRange(32, 64)
        raw.fill(0)
        return VaultKey(cipherKey, macKey)
    }

    private fun requirePassphrase(passphrase: String) {
        require(passphrase.length >= minPassphraseLength) {
            "口令至少需要 $minPassphraseLength 个字符"
        }
    }

    companion object {
        /**
         * The minimum passphrase length.
         *
         * A longer minimum raises the entropy floor that Argon2id has to work with.
         * It cannot make a weak passphrase strong, but it does rule out the
         * handful-of-characters choices that dominate real-world breach lists.
         */
        const val MIN_PASSPHRASE_LENGTH = 10
    }
}

/** Decodes lowercase hex into bytes. */
internal fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string has an odd length" }
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(hex[i * 2], 16)
        val lo = Character.digit(hex[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) { "hex string contains a non-hex character" }
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

/** Encodes bytes as lowercase hex. */
internal fun bytesToHex(bytes: ByteArray): String =
    buildString(bytes.size * 2) {
        for (b in bytes) append("%02x".format(b))
    }
