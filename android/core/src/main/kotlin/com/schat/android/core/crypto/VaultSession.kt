package com.schat.android.core.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The vault parameters that are **not** secret.
 *
 * The salt, the Argon2id profile and a verifier have to be readable before the vault
 * can be unlocked, so they cannot live inside the encrypted store: needing the key to
 * read the salt that derives the key is circular. All three are safe in the clear. The
 * salt is not secret by construction; the profile only says how expensive the
 * derivation is; and the verifier is an HMAC under a key that is itself derived from
 * the passphrase, so it reveals nothing an attacker could not compute anyway — it just
 * lets an honest client say "wrong passphrase" instead of "corrupt data".
 */
data class VaultMetadata(
    /** 32 random bytes as lowercase hex. */
    val saltHex: String,

    /** The Argon2id cost profile the vault was created with. */
    val profile: String,

    /** HMAC-SHA256 of [VERIFY_LABEL] under the vault's MAC key. */
    val verifier: String,
)

/**
 * Persists the non-secret vault metadata.
 *
 * Plain storage is correct here and the interface makes that explicit, so no future
 * reader has to wonder whether putting it in the clear was an oversight.
 */
interface MetadataStore {
    fun read(): VaultMetadata?
    fun write(metadata: VaultMetadata)
    fun clear()
}

/**
 * Creates and unlocks the vault.
 *
 * # Why a verifier exists
 *
 * Argon2id cannot tell a wrong passphrase from a right one: it produces a different
 * key either way, and there is no such thing as a "close" match. Without a verifier
 * the first sign of a typo would be a store that fails to decrypt, which is
 * indistinguishable from a corrupted or tampered store — a far more alarming message
 * for what is usually a slip of the thumb.
 *
 * The verifier is checked with a constant-time comparison. It is not a high-value
 * secret, but leaking how many leading bytes of an HMAC matched is free information
 * and costs nothing to withhold.
 */
class VaultSession(
    private val deriver: KeyDeriver,
    private val deviceKeys: DeviceKeyProvider,
    private val metadata: MetadataStore,
    private val defaultProfile: String = VaultProfile.BALANCED,
) {
    /** True once a vault has been created on this device. */
    val isInitialised: Boolean
        get() = metadata.read() != null

    /** The Argon2id profile this vault uses, or the default before it exists. */
    fun profile(): String = metadata.read()?.profile ?: defaultProfile

    /**
     * Creates the vault with a fresh salt and records its metadata.
     *
     * It refuses to run twice: re-creating a vault under a new passphrase would leave
     * the existing encrypted data unreadable while looking like a successful setup.
     *
     * # Why the profile can step down
     *
     * Argon2id's cost *is* memory, so the balanced profile asks the process to allocate
     * 64 MiB. On a memory-constrained device that allocation can fail outright, and the
     * original behaviour was to fail the whole vault creation — leaving the user stuck
     * at the start of setup with their passphrase and recovery code already entered.
     *
     * The profile that actually succeeded is what gets recorded, so unlocking later
     * derives with the same cost. Falling back to 32 MiB is a real, if modest,
     * reduction in brute-force resistance; failing to create a vault at all is worse,
     * and the alternative — silently storing plaintext — is not on the table.
     */
    fun create(passphrase: String): VaultKey {
        check(!isInitialised) { "vault already initialised" }

        val deviceKey = deviceKeys.deviceKeyHex()
        val vault = Vault(deriver)

        var profile = defaultProfile
        val created = try {
            vault.create(passphrase, deviceKey, profile)
        } catch (primary: Exception) {
            if (profile == VaultProfile.LOW) throw primary
            profile = VaultProfile.LOW
            vault.create(passphrase, deviceKey, profile)
        }

        metadata.write(VaultMetadata(created.saltHex, profile, verifier(created.key)))
        return created.key
    }

    /**
     * Unlocks the vault, or returns null.
     *
     * A null result means exactly one thing — the passphrase is wrong, or the device
     * key no longer matches — and the returned key must be destroyed by the caller
     * once the store has been opened.
     */
    fun unlock(passphrase: String): VaultKey? {
        val meta = metadata.read() ?: return null

        val key = Vault(deriver).unlock(
            passphrase = passphrase,
            saltHex = meta.saltHex,
            deviceKeyHex = deviceKeys.deviceKeyHex(),
            profile = meta.profile,
        ) ?: return null

        val expected = decodeHex(meta.verifier)
        val actual = verifierBytes(key)
        if (expected == null || !MessageDigest.isEqual(expected, actual)) {
            key.destroy()
            return null
        }
        return key
    }

    /** Removes the metadata, which makes every existing store unreadable. */
    fun reset() {
        metadata.clear()
    }
}

/** The label hashed to produce the verifier. Changing it invalidates existing vaults. */
private const val VERIFY_LABEL = "schat-vault-verify-v1"

/** The hex form of the verifier, as stored. */
internal fun verifier(key: VaultKey): String =
    verifierBytes(key).joinToString("") { "%02x".format(it) }

/**
 * HMAC-SHA256 of the verify label under the vault's MAC key.
 *
 * HMAC rather than a plain hash: the MAC key is the half of the vault key that exists
 * for exactly this kind of purpose, and using it keeps the cipher key out of the
 * comparison entirely.
 */
internal fun verifierBytes(key: VaultKey): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key.macKey, "HmacSHA256"))
    return mac.doFinal(VERIFY_LABEL.toByteArray(Charsets.UTF_8))
}

private fun decodeHex(hex: String): ByteArray? = try {
    require(hex.length % 2 == 0)
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(hex[i * 2], 16)
        val lo = Character.digit(hex[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0)
        out[i] = ((hi shl 4) or lo).toByte()
    }
    out
} catch (e: Exception) {
    null
}
