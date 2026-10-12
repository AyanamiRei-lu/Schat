package com.schat.android.core.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android-specific implementations of the vault's hardware binding.
 *
 * These live in :app rather than :core because they need the Keystore. Everything
 * they *decide* is expressed through the [DeviceKeyProvider] and [SeedStore]
 * contracts in :core, which are exercised there against fakes.
 */

/**
 * Persists the wrapped device seed.
 *
 * An interface so that tests, and any future migration off the Keystore, do not have
 * to go through [AndroidDeviceKeyProvider].
 */
interface SeedStore {
    /** Returns the unwrapped seed, or null when none has been stored yet. */
    fun readSeed(alias: String): ByteArray?

    /** Wraps and persists the seed, replacing any previous value. */
    fun writeSeed(alias: String, seed: ByteArray)

    /** True when the wrapping key lives in a dedicated security chip. */
    fun isHardwareBacked(alias: String): Boolean
}

/**
 * The Android implementation of [DeviceKeyProvider].
 *
 * # Why this wraps a random seed instead of using a Keystore key directly
 *
 * The obvious design — "put a 256-bit key in the Keystore and feed its bytes into
 * Argon2id" — does not work, and the failure is worth stating plainly because it is
 * silent rather than loud: a Keystore key marked non-exportable **cannot be read
 * out**. There is no API that returns its bytes. That is exactly the property that
 * makes it valuable, and it is also why it cannot be an Argon2id input.
 *
 * So the Keystore key is used for what it can do: it *wraps* a random 32-byte vault
 * seed. The seed is generated on first run and stored encrypted under a Keystore AES
 * key that never leaves the TEE. Unlocking therefore requires the device, because
 * unwrapping the seed requires the hardware key; and because the seed is itself
 * random and stored only in ciphertext, an attacker who exfiltrates app storage gets
 * nothing usable.
 *
 * The device-binding guarantee is exactly as strong as the Keystore's hold on the
 * wrapping key, which is the strongest thing Android offers.
 */
class AndroidDeviceKeyProvider(
    private val seedStore: SeedStore,
    private val keyAlias: String = DEFAULT_ALIAS,
) : DeviceKeyProvider {

    private var cached: String? = null

    override fun deviceKeyHex(): String {
        cached?.let { return it }

        val seed = seedStore.readSeed(keyAlias) ?: run {
            val fresh = ByteArray(32).also { SecureRandom().nextBytes(it) }
            seedStore.writeSeed(keyAlias, fresh)
            fresh
        }

        val hex = seed.joinToString("") { "%02x".format(it) }
        // The seed itself is no longer needed; only its hex form is cached, and only
        // for the lifetime of this object.
        seed.fill(0)
        cached = hex
        return hex
    }

    override fun isHardwareBacked(): Boolean = seedStore.isHardwareBacked(keyAlias)

    companion object {
        /** The Keystore alias holding the wrapping key. */
        const val DEFAULT_ALIAS = "schat.device.kek.v1"
    }
}

/**
 * The real [SeedStore], backed by the Android Keystore and an app-private file.
 *
 * The wrapped seed is written to a file the app owns. That file is not itself secret
 * — it is ciphertext under a hardware key — but it is written with the app's private
 * storage permissions regardless.
 */
class KeystoreSeedStore(private val seedFile: java.io.File) : SeedStore {

    override fun readSeed(alias: String): ByteArray? {
        val blob = try {
            if (!seedFile.exists()) return null
            seedFile.readBytes()
        } catch (e: Exception) {
            return null
        }
        if (blob.size < GCM_IV_BYTES + 1) return null

        return try {
            val key = existingKey(alias) ?: return null
            val iv = blob.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)

            // Passing an IV IS permitted for decryption — and is required, because the
            // IV used at encryption time is the only one that can work.
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // A seed that cannot be unwrapped means the hardware key is gone, for
            // example after a device restore. Returning null makes the caller generate
            // a fresh one, which correctly leaves the old vault unreadable rather than
            // pretending it can still be opened.
            null
        }
    }

    override fun writeSeed(alias: String, seed: ByteArray) {
        val key = existingKey(alias) ?: generateKey(alias)

        val cipher = Cipher.getInstance(TRANSFORMATION)

        // AndroidKeyStore OWNS the IV for its AES/GCM keys: supplying one is rejected
        // with InvalidAlgorithmParameterException("Caller-provided IV not permitted").
        // The provider generates the IV during init, and it is read back afterwards.
        //
        // This was the defect that made every vault creation fail on a real device
        // while the same code passed every JVM test — a plain SecretKeySpec accepts a
        // caller-supplied IV, so nothing off-device can catch this.
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv ?: throw IllegalStateException("the keystore produced no IV")
        val ciphertext = cipher.doFinal(seed)

        seedFile.parentFile?.mkdirs()
        seedFile.writeBytes(iv + ciphertext)
    }

    override fun isHardwareBacked(alias: String): Boolean = try {
        val secretKey = existingKey(alias) ?: return false
        val factory = javax.crypto.SecretKeyFactory.getInstance(secretKey.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(secretKey, android.security.keystore.KeyInfo::class.java)
                as android.security.keystore.KeyInfo

        @Suppress("DEPRECATION")
        info.isInsideSecureHardware
    } catch (e: Exception) {
        false
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun existingKey(alias: String): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun generateKey(alias: String): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // No setUserAuthenticationRequired: the vault already requires the user's
            // passphrase, and demanding biometrics as well would lock users out of
            // their own history the moment a fingerprint sensor fails.
            .build()

        generator.init(spec)
        return generator.generateKey()
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
    }
}
