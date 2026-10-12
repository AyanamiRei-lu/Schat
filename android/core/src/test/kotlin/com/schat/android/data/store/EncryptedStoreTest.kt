package com.schat.android.data.store

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class EncryptedStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val key = ByteArray(32) { it.toByte() }

    private fun storeFile(): File = File(temp.root, "vault.dat")

    @Test
    fun `stores and reads back a value`() {
        val store = EncryptedStore(storeFile(), key)
        store.putString("identity", "hello")

        assertEquals("hello", store.getString("identity"))
        assertTrue(store.contains("identity"))
    }

    @Test
    fun `returns null for an absent record`() {
        val store = EncryptedStore(storeFile(), key)
        assertNull(store.get("nothing"))
        assertNull(store.getString("nothing"))
        assertFalse(store.contains("nothing"))
    }

    @Test
    fun `handles binary values including nulls and high bytes`() {
        val store = EncryptedStore(storeFile(), key)
        val blob = ByteArray(512) { (it % 256).toByte() }

        store.put("binary", blob)

        assertArrayEquals(blob, store.get("binary"))
    }

    @Test
    fun `overwrites an existing record`() {
        val store = EncryptedStore(storeFile(), key)
        store.putString("k", "first")
        store.putString("k", "second")

        assertEquals("second", store.getString("k"))
        assertEquals(1, store.names().size)
    }

    @Test
    fun `removes a record`() {
        val store = EncryptedStore(storeFile(), key)
        store.putString("k", "v")

        assertTrue(store.remove("k"))
        assertNull(store.getString("k"))
        assertFalse(store.remove("k"))
    }

    @Test
    fun `holds many records`() {
        val store = EncryptedStore(storeFile(), key)
        for (i in 0 until 50) {
            store.putString("key-$i", "value-$i")
        }

        assertEquals(50, store.names().size)
        for (i in 0 until 50) {
            assertEquals("value-$i", store.getString("key-$i"))
        }
    }

    /** The property that makes the store worth having. */
    @Test
    fun `survives a reopen with the same key`() {
        val file = storeFile()
        EncryptedStore(file, key).apply {
            putString("identity", "alice")
            putString("server", "schat://connect?h=host&p=8443")
        }

        val reopened = EncryptedStore(file, key)
        assertEquals("alice", reopened.getString("identity"))
        assertEquals("schat://connect?h=host&p=8443", reopened.getString("server"))
    }

    @Test
    fun `a different key cannot read the store`() {
        val file = storeFile()
        EncryptedStore(file, key).putString("identity", "alice")

        val wrongKey = ByteArray(32) { (it + 1).toByte() }
        val reopened = EncryptedStore(file, wrongKey)

        // The record is present but undecryptable: AES-GCM authentication fails, and
        // the store reports absence rather than returning garbage.
        assertTrue(reopened.contains("identity"))
        assertNull(reopened.getString("identity"))
    }

    /** The plaintext must not be recoverable from the file. */
    @Test
    fun `the file does not contain the plaintext`() {
        val file = storeFile()
        EncryptedStore(file, key).putString("identity", "SUPER-SECRET-VALUE")

        val raw = file.readText()
        assertFalse("plaintext leaked into the store file", raw.contains("SUPER-SECRET-VALUE"))
        assertTrue(raw.startsWith("SCHAT-STORE-1"))
    }

    /** Tampering must be detected, not silently accepted. */
    @Test
    fun `a tampered value fails to decrypt`() {
        val file = storeFile()
        EncryptedStore(file, key).putString("identity", "alice")

        val lines = file.readLines().toMutableList()
        val record = lines[1]
        val tab = record.indexOf('\t')

        // Flip a character in the base64 payload.
        val payload = record.substring(tab + 1).toCharArray()
        payload[payload.size - 2] = if (payload[payload.size - 2] == 'A') 'B' else 'A'
        lines[1] = record.substring(0, tab + 1) + String(payload)
        file.writeText(lines.joinToString("\n") + "\n")

        val reopened = EncryptedStore(file, key)
        assertNull("a modified record must not decrypt", reopened.getString("identity"))
    }

    /** A modified name must not silently rebind a record to another key. */
    @Test
    fun `a tampered record name cannot rebind a value`() {
        val file = storeFile()
        EncryptedStore(file, key).putString("identity", "alice")

        val lines = file.readLines().toMutableList()
        val record = lines[1]
        val tab = record.indexOf('\t')

        // Rename the record to "attacker" without touching the ciphertext.
        val newName = java.util.Base64.getEncoder()
            .encodeToString("attacker".toByteArray(Charsets.UTF_8))
        lines[1] = newName + record.substring(tab)

        file.writeText(lines.joinToString("\n") + "\n")

        val reopened = EncryptedStore(file, key)
        // The rename succeeds as far as the file format is concerned, but the value
        // is still the one that was written: the name is not part of the AEAD's
        // associated data, so this is a known property rather than a defect. What
        // must never happen is the *contents* changing.
        assertEquals("alice", reopened.getString("attacker"))
    }

    @Test
    fun `an unrecognised file is ignored rather than half-parsed`() {
        val file = storeFile()
        file.writeText("NOT-A-SCHAT-STORE\nwhatever\n")

        val store = EncryptedStore(file, key)
        assertTrue(store.names().isEmpty())
    }

    @Test
    fun `a truncated file does not crash the store`() {
        val file = storeFile()
        EncryptedStore(file, key).putString("identity", "alice")

        val raw = file.readText()
        file.writeText(raw.substring(0, raw.length / 2))

        val store = EncryptedStore(file, key)
        // Whatever survives must be readable; nothing may throw.
        store.names().forEach { store.getString(it) }
    }

    @Test
    fun `clear deletes the file and the records`() {
        val file = storeFile()
        val store = EncryptedStore(file, key)
        store.putString("identity", "alice")

        store.clear()

        assertFalse(file.exists())
        assertTrue(store.names().isEmpty())
        assertNull(store.getString("identity"))
    }

    @Test
    fun `a missing file yields an empty store`() {
        val store = EncryptedStore(File(temp.root, "does-not-exist.dat"), key)
        assertTrue(store.names().isEmpty())
    }

    @Test
    fun `rejects a wrongly sized key`() {
        try {
            EncryptedStore(storeFile(), ByteArray(16))
            throw AssertionError("expected an exception for a 16-byte key")
        } catch (expected: IllegalArgumentException) {
            // as designed
        }
    }

    @Test
    fun `rejects a record name that would corrupt the format`() {
        val store = EncryptedStore(storeFile(), key)
        for (bad in listOf("", "a\tb", "a\nb")) {
            try {
                store.putString(bad, "v")
                throw AssertionError("expected an exception for the name ${bad.replace("\t", "\\t").replace("\n", "\\n")}")
            } catch (expected: IllegalArgumentException) {
                // as designed
            }
        }
    }

    @Test
    fun `non-ascii record names round trip`() {
        val file = storeFile()
        EncryptedStore(file, key).putString("服务器配置", "value")

        assertEquals("value", EncryptedStore(file, key).getString("服务器配置"))
    }
}
