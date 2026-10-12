package com.schat.android.core.crypto

import com.schat.android.core.profile.ClientProfileData
import com.schat.android.core.profile.ClientProfileStore
import com.schat.android.data.store.EncryptedStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.MessageDigest

/**
 * A deterministic stand-in for the Go core. Not cryptography; it exists so the vault
 * wiring can be exercised on the JVM.
 */
private class FakeDeriver : KeyDeriver {
    override fun newSalt() = "11".repeat(32)
    override fun newRouteKey() = "22".repeat(32)
    override fun deriveVaultKey(
        passphrase: String,
        saltHex: String,
        deviceKeyHex: String,
        profile: String,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(passphrase.toByteArray())
        digest.update(saltHex.toByteArray())
        digest.update(deviceKeyHex.toByteArray())
        val first = digest.digest()
        digest.update(first)
        return (first + digest.digest()).joinToString("") { "%02x".format(it) }
    }
}

private class FakeDeviceKeys(private val hex: String = "aa".repeat(32)) : DeviceKeyProvider {
    override fun deviceKeyHex() = hex
    override fun isHardwareBacked() = true
}

private class InMemoryMetadataStore : MetadataStore {
    private var value: VaultMetadata? = null
    var writes = 0
    override fun read() = value
    override fun write(metadata: VaultMetadata) { value = metadata; writes++ }
    override fun clear() { value = null }
}

class VaultSessionTest {

    private val passphrase = "correct horse battery staple"

    private fun session(
        store: MetadataStore = InMemoryMetadataStore(),
        deviceKeys: DeviceKeyProvider = FakeDeviceKeys(),
    ) = VaultSession(FakeDeriver(), deviceKeys, store)

    @Test
    fun `a new device has no vault`() {
        val s = session()
        assertFalse(s.isInitialised)
        assertNull(s.unlock(passphrase))
    }

    @Test
    fun `create records metadata and yields a usable key`() {
        val meta = InMemoryMetadataStore()
        val s = session(meta)

        val key = s.create(passphrase)

        assertTrue(s.isInitialised)
        assertEquals(1, meta.writes)
        // Bytes, not hex characters: the derived 64-byte material is split in half.
        assertEquals(32, key.cipherKey.size)
        assertEquals(32, key.macKey.size)

        val m = meta.read()!!
        assertEquals(64, m.saltHex.length)
        assertEquals(VaultProfile.BALANCED, m.profile)
        assertEquals(64, m.verifier.length) // 32 bytes as hex
    }

    @Test
    fun `create refuses to run twice`() {
        val s = session()
        s.create(passphrase)

        try {
            s.create(passphrase)
            throw AssertionError("expected an exception when re-creating a vault")
        } catch (expected: IllegalStateException) {
            // as designed: re-creating would orphan the existing data
        }
    }

    @Test
    fun `unlock with the right passphrase reproduces the key`() {
        val s = session()
        val created = s.create(passphrase)

        val unlocked = s.unlock(passphrase)
        assertNotNull(unlocked)
        assertTrue(created.cipherKey.contentEquals(unlocked!!.cipherKey))
        assertTrue(created.macKey.contentEquals(unlocked.macKey))
    }

    /** The verifier's whole purpose: reject a typo cleanly. */
    @Test
    fun `unlock with a wrong passphrase returns null`() {
        val s = session()
        s.create(passphrase)

        assertNull(s.unlock("wrong passphrase entirely"))
    }

    @Test
    fun `unlock with a wrong device key returns null`() {
        val meta = InMemoryMetadataStore()
        session(meta).create(passphrase)

        // Same metadata, same passphrase, different device: the derived key differs and
        // the verifier catches it.
        val otherDevice = VaultSession(FakeDeriver(), FakeDeviceKeys("bb".repeat(32)), meta)
        assertNull(otherDevice.unlock(passphrase))
    }

    @Test
    fun `unlock is case and whitespace sensitive`() {
        val s = session()
        s.create(passphrase)

        assertNull(s.unlock(passphrase.uppercase()))
        assertNull(s.unlock("$passphrase "))
    }

    @Test
    fun `a corrupted verifier is treated as a failed unlock`() {
        val meta = InMemoryMetadataStore()
        val s = session(meta)
        s.create(passphrase)

        meta.write(meta.read()!!.copy(verifier = "00".repeat(32)))
        assertNull(s.unlock(passphrase))
    }

    @Test
    fun `a malformed verifier is treated as a failed unlock`() {
        val meta = InMemoryMetadataStore()
        val s = session(meta)
        s.create(passphrase)

        meta.write(meta.read()!!.copy(verifier = "not hex"))
        assertNull(s.unlock(passphrase))
    }

    @Test
    fun `reset makes the vault disappear`() {
        val s = session()
        s.create(passphrase)

        s.reset()

        assertFalse(s.isInitialised)
        assertNull(s.unlock(passphrase))
    }

    @Test
    fun `the profile is reported and defaults before creation`() {
        val s = session()
        assertEquals(VaultProfile.BALANCED, s.profile())
        s.create(passphrase)
        assertEquals(VaultProfile.BALANCED, s.profile())
    }

    @Test
    fun `the verifier depends on the mac key only`() {
        val a = VaultKey(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val sameKey = VaultKey(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val otherMac = VaultKey(ByteArray(32) { 1 }, ByteArray(32) { 3 })
        val otherCipher = VaultKey(ByteArray(32) { 9 }, ByteArray(32) { 2 })

        assertEquals(verifier(a), verifier(sameKey))
        assertNotEquals(verifier(a), verifier(otherMac))
        // The cipher key is deliberately not part of the verifier.
        assertEquals(verifier(a), verifier(otherCipher))
    }
}

class ClientProfileStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val key = ByteArray(32) { it.toByte() }

    private fun store(file: File = File(temp.root, "vault.dat")) = EncryptedStore(file, key)

    private fun sample() = ClientProfileData(
        identityJson = """{"signing_public":"aa","agreement_public":"bb"}""",
        prekeyStoreJson = """{"signed_pre_key_id":1}""",
        routeKeyHex = "22".repeat(32),
        recoveryCode = "acorn actor adapt agile",
        serverUri = "schat://connect?h=192.168.1.158&p=8443&ss=1&fp=${"11".repeat(32)}",
    )

    @Test
    fun `an empty store has no profile`() {
        val s = ClientProfileStore(store())
        assertFalse(s.isComplete())
        assertNull(s.load())
    }

    @Test
    fun `saves and loads the whole profile`() {
        val s = ClientProfileStore(store())
        val data = sample()

        s.save(data)

        assertTrue(s.isComplete())
        assertEquals(data, s.load())
    }

    /** The property the client actually depends on across a restart. */
    @Test
    fun `the profile survives a reopen of the store`() {
        val file = File(temp.root, "vault.dat")
        ClientProfileStore(store(file)).save(sample())

        val reopened = ClientProfileStore(store(file))
        assertEquals(sample(), reopened.load())
    }

    @Test
    fun `a partially present profile loads as null rather than half filled`() {
        val raw = store()
        raw.putString("profile.identity", "{}")
        raw.putString("profile.server", "schat://connect?h=h")

        val s = ClientProfileStore(raw)
        assertFalse(s.isComplete())
        assertNull(s.load())
    }

    @Test
    fun `clear removes every record`() {
        val s = ClientProfileStore(store())
        s.save(sample())

        s.clear()

        assertFalse(s.isComplete())
        assertNull(s.load())
    }

    @Test
    fun `saving twice replaces rather than duplicates`() {
        val s = ClientProfileStore(store())
        s.save(sample())
        val updated = sample().copy(recoveryCode = "different words entirely")
        s.save(updated)

        assertEquals(updated, s.load())
    }

    /** The profile must not be readable from disk without the key. */
    @Test
    fun `profile contents do not appear in the file`() {
        val file = File(temp.root, "vault.dat")
        ClientProfileStore(store(file)).save(sample())

        val raw = file.readText()
        assertFalse(raw.contains("acorn actor adapt agile"))
        assertFalse(raw.contains("192.168.1.158"))
    }
}

/**
 * A deriver that fails for one profile.
 *
 * It models the real failure this fallback exists for: Argon2id's cost is memory, and
 * a device that cannot allocate the balanced profile's 64 MiB throws rather than
 * returning a key.
 */
private class PickyDeriver(private val failProfile: String) : KeyDeriver {
    override fun newSalt() = "11".repeat(32)
    override fun newRouteKey() = "22".repeat(32)
    override fun deriveVaultKey(
        passphrase: String,
        saltHex: String,
        deviceKeyHex: String,
        profile: String,
    ): String {
        if (profile == failProfile) {
            throw IllegalStateException("cannot allocate the $profile profile")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("$passphrase|$saltHex|$deviceKeyHex|$profile".toByteArray())
        val first = digest.digest()
        digest.update(first)
        return (first + digest.digest()).joinToString("") { "%02x".format(it) }
    }
}

class VaultProfileFallbackTest {

    private val passphrase = "correct horse battery staple"

    /**
     * The failure that made vault creation impossible on a real device: the balanced
     * profile could not be allocated, and the whole setup was abandoned.
     */
    @Test
    fun `falls back to the low profile when the default cannot be allocated`() {
        val meta = InMemoryMetadataStore()
        val session = VaultSession(PickyDeriver(VaultProfile.BALANCED), FakeDeviceKeys(), meta)

        val key = session.create(passphrase)

        assertEquals(32, key.cipherKey.size)
        assertEquals(VaultProfile.LOW, meta.read()!!.profile)
        assertTrue(session.isInitialised)
    }

    /** The recorded profile is what unlocking uses, so the two must agree. */
    @Test
    fun `a vault created with the fallback unlocks again`() {
        val meta = InMemoryMetadataStore()
        val first = VaultSession(PickyDeriver(VaultProfile.BALANCED), FakeDeviceKeys(), meta)
        val created = first.create(passphrase)

        val second = VaultSession(PickyDeriver(VaultProfile.BALANCED), FakeDeviceKeys(), meta)
        val unlocked = second.unlock(passphrase)

        assertNotNull(unlocked)
        assertTrue(created.cipherKey.contentEquals(unlocked!!.cipherKey))
    }

    /** The fallback must not become a way to hide a total failure. */
    @Test
    fun `a failure at the lowest profile is still reported`() {
        // Every profile fails, so the fallback is attempted and then must give up
        // rather than report a vault that does not exist.
        val alwaysFails = object : KeyDeriver {
            override fun newSalt() = "11".repeat(32)
            override fun newRouteKey() = "22".repeat(32)
            override fun deriveVaultKey(
                passphrase: String,
                saltHex: String,
                deviceKeyHex: String,
                profile: String,
            ): String = throw IllegalStateException("cannot allocate the $profile profile")
        }
        val meta = InMemoryMetadataStore()
        val session = VaultSession(alwaysFails, FakeDeviceKeys(), meta)

        try {
            session.create(passphrase)
            throw AssertionError("expected the failure to propagate")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message.orEmpty().contains("low"))
        }
        // And nothing may have been recorded, or the next launch would demand an
        // unlock for a vault that cannot be opened.
        assertNull(meta.read())
    }

    /** The default profile must be tried first, not skipped. */
    @Test
    fun `the default profile is used when it works`() {
        val meta = InMemoryMetadataStore()
        val session = VaultSession(PickyDeriver("none"), FakeDeviceKeys(), meta)

        session.create(passphrase)

        assertEquals(VaultProfile.BALANCED, meta.read()!!.profile)
    }
}
