package com.schat.android.data.store

import java.io.File
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A file-backed key/value store whose values are encrypted with AES-256-GCM.
 *
 * # What this is, and what it is not
 *
 * This is the step-4 store: it holds the handful of small records a client needs
 * before it has any message history — the identity key pair, the prekey pool, the
 * route key, the server configuration. It is deliberately not a database.
 *
 * A real message store arrives in step 5, and the choice there will be between
 * SQLCipher and an encrypted page store of our own. Starting with a JSON-free,
 * line-oriented file keeps step 4 free of a large native dependency while the data
 * volume is still trivial, and the interface here is small enough that replacing the
 * implementation later does not reach the callers.
 *
 * # Why the file needs no separate integrity layer
 *
 * Every value is an independent AES-GCM record with its own nonce and tag, so a
 * modified value fails to decrypt and a removed one is simply absent. The file as a
 * whole has no rollback protection: an attacker with write access to app storage
 * could restore an older copy. On a non-rooted device that attacker does not exist,
 * and on a rooted one they have the app's own keys anyway. It is recorded here so the
 * boundary is explicit rather than assumed.
 *
 * # Format
 *
 * ```
 * SCHAT-STORE-1
 * <base64 key>\t<base64 iv||ciphertext||tag>
 * ...
 * ```
 *
 * A hand-rolled line format rather than JSON, because `org.json` is present on
 * Android but throws on a plain JVM, and this class is meant to be unit tested
 * there.
 */
class EncryptedStore(
    private val file: File,
    cipherKey: ByteArray,
) {
    private val key: SecretKeySpec

    /** Base64-encoded records, keyed by their plaintext name. */
    private val records = LinkedHashMap<String, String>()

    init {
        require(cipherKey.size == 32) { "cipher key must be 32 bytes, got ${cipherKey.size}" }
        key = SecretKeySpec(cipherKey.copyOf(), "AES")
        if (file.exists()) {
            load()
        }
    }

    /** Returns the value for [name], or null when it is absent. */
    fun get(name: String): ByteArray? {
        val record = records[name] ?: return null
        return decrypt(record)
    }

    /** Returns the value for [name] as UTF-8 text, or null. */
    fun getString(name: String): String? = get(name)?.toString(Charsets.UTF_8)

    /** Stores a value, replacing any previous one, and flushes to disk. */
    fun put(name: String, value: ByteArray) {
        require(name.isNotEmpty()) { "record name must not be empty" }
        require(!name.contains('\t') && !name.contains('\n')) {
            "record name must not contain a tab or newline"
        }
        records[name] = encrypt(value)
        persist()
    }

    /** Stores a UTF-8 string value. */
    fun putString(name: String, value: String) = put(name, value.toByteArray(Charsets.UTF_8))

    /** Removes a record. Returns true when something was removed. */
    fun remove(name: String): Boolean {
        if (records.remove(name) == null) return false
        persist()
        return true
    }

    /** True when a record exists. */
    fun contains(name: String): Boolean = records.containsKey(name)

    /** The names of all stored records. */
    fun names(): Set<String> = records.keys.toSet()

    /**
     * Deletes the backing file and clears memory.
     *
     * It does not overwrite the file first. On flash storage a secure erase is not
     * achievable from an application anyway — wear levelling keeps the old blocks —
     * so pretending otherwise would be worse than saying so.
     */
    fun clear() {
        records.clear()
        if (file.exists()) {
            file.delete()
        }
    }

    // ----------------------------------------------------------------------

    private fun encrypt(value: ByteArray): String {
        val iv = ByteArray(GCM_IV_BYTES)
        SECURE_RANDOM.nextBytes(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ciphertext = cipher.doFinal(value)

        return Base64.getEncoder().encodeToString(iv + ciphertext)
    }

    private fun decrypt(record: String): ByteArray? = try {
        val blob = Base64.getDecoder().decode(record)
        if (blob.size < GCM_IV_BYTES + GCM_TAG_BITS / 8) {
            null
        } else {
            val iv = blob.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        }
    } catch (e: Exception) {
        // A tampered or truncated value fails here. Returning null rather than
        // throwing keeps a corrupted record from taking down the whole store, and
        // the caller cannot mistake it for a successful read.
        null
    }

    private fun load() {
        val lines = try {
            file.readLines()
        } catch (e: Exception) {
            return
        }
        if (lines.isEmpty() || lines[0].trim() != MAGIC) {
            // A file we do not recognise is ignored rather than half-parsed. It can
            // only be a corrupt or foreign file, and merging it would be worse.
            return
        }

        for (line in lines.drop(1)) {
            if (line.isBlank()) continue
            val tab = line.indexOf('\t')
            if (tab <= 0) continue

            val name = try {
                String(Base64.getDecoder().decode(line.substring(0, tab)), Charsets.UTF_8)
            } catch (e: Exception) {
                continue
            }
            records[name] = line.substring(tab + 1)
        }
    }

    private fun persist() {
        val builder = StringBuilder()
        builder.append(MAGIC).append('\n')
        for ((name, record) in records) {
            val encodedName = Base64.getEncoder().encodeToString(name.toByteArray(Charsets.UTF_8))
            builder.append(encodedName).append('\t').append(record).append('\n')
        }

        // Write to a sibling and rename, so a crash mid-write cannot leave a
        // half-written store behind: rename is atomic on the same filesystem.
        val temp = File(file.parentFile, file.name + ".tmp")
        temp.parentFile?.mkdirs()
        temp.writeText(builder.toString())

        if (!temp.renameTo(file)) {
            // Windows refuses rename onto an existing file; fall back to a delete.
            file.delete()
            if (!temp.renameTo(file)) {
                temp.copyTo(file, overwrite = true)
                temp.delete()
            }
        }
    }

    private companion object {
        const val MAGIC = "SCHAT-STORE-1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128

        val SECURE_RANDOM = java.security.SecureRandom()
    }
}
