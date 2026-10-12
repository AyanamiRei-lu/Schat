package com.schat.android.core.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * A deterministic stand-in for the Go protocol core.
 *
 * It is NOT cryptography and must never be mistaken for it: it exists so the vault
 * logic (policy, salt handling, key splitting, failure behaviour) can be tested on
 * the JVM. The real derivation is covered by the Go test suite in protocol/mobile,
 * which does run the actual Argon2id and the actual AAD-free combination.
 *
 * It does model the property that matters for these tests: the output depends on the
 * passphrase, the salt AND the device key, so a test can prove that all three reach
 * the deriver.
 */
private class FakeKeyDeriver : KeyDeriver {
    var lastProfile: String? = null
    var callCount = 0

    override fun newSalt(): String = "1111111111111111111111111111111111111111111111111111111111111111"

    override fun newRouteKey(): String = "2222222222222222222222222222222222222222222222222222222222222222"

    override fun deriveVaultKey(
        passphrase: String,
        saltHex: String,
        deviceKeyHex: String,
        profile: String,
    ): String {
        callCount++
        lastProfile = profile

        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(passphrase.toByteArray())
        digest.update(saltHex.toByteArray())
        digest.update(deviceKeyHex.toByteArray())

        // Two blocks so the result is the 64 bytes the real core produces.
        val first = digest.digest()
        digest.update(first)
        val second = digest.digest()
        return (first + second).joinToString("") { "%02x".format(it) }
    }
}

class VaultTest {

    private val deviceKey = "aa".repeat(32)
    private val passphrase = "correct horse battery staple"

    private fun vault() = Vault(FakeKeyDeriver())

    @Test
    fun `create returns a salt and a usable key`() {
        val created = vault().create(passphrase, deviceKey)

        assertEquals(64, created.saltHex.length)
        assertEquals(32, created.key.cipherKey.size)
        assertEquals(32, created.key.macKey.size)
        // The two halves must differ, or the split is not doing anything.
        assertFalse(created.key.cipherKey.contentEquals(created.key.macKey))
    }

    @Test
    fun `unlock reproduces the same key as create`() {
        val v = vault()
        val created = v.create(passphrase, deviceKey)

        val unlocked = v.unlock(passphrase, created.saltHex, deviceKey)
        assertNotNull(unlocked)
        assertTrue(created.key.cipherKey.contentEquals(unlocked!!.cipherKey))
        assertTrue(created.key.macKey.contentEquals(unlocked.macKey))
    }

    @Test
    fun `a different passphrase fails`() {
        val v = vault()
        val created = v.create(passphrase, deviceKey)

        // The fake deriver always "succeeds"; a real one would too, because Argon2id
        // output has no way to be recognised as wrong. What must differ is the key,
        // which is why the store's authentication tag is the real check.
        val wrong = v.unlock("wrong passphrase entirely", created.saltHex, deviceKey)
        assertNotNull(wrong)
        assertFalse(created.key.cipherKey.contentEquals(wrong!!.cipherKey))
    }

    @Test
    fun `a different device key produces a different vault key`() {
        val v = vault()
        val created = v.create(passphrase, deviceKey)

        val other = v.unlock(passphrase, created.saltHex, "bb".repeat(32))
        assertNotNull(other)
        assertFalse(
            "the device key must contribute to the derivation",
            created.key.cipherKey.contentEquals(other!!.cipherKey),
        )
    }

    @Test
    fun `a different salt produces a different vault key`() {
        val v = vault()
        val a = v.create(passphrase, deviceKey)
        // Force a different salt by deriving against another one.
        val b = v.unlock(passphrase, "33".repeat(32), deviceKey)

        assertNotNull(b)
        assertNotEquals(
            a.key.cipherKey.toHex(),
            b!!.cipherKey.toHex(),
        )
    }

    @Test
    fun `short passphrases are refused at creation`() {
        try {
            vault().create("short", deviceKey)
            throw AssertionError("expected an exception for a short passphrase")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("10"))
        }
    }

    @Test
    fun `short passphrases are refused at unlock`() {
        val v = vault()
        val created = v.create(passphrase, deviceKey)

        assertNull(v.unlock("short", created.saltHex, deviceKey))
    }

    @Test
    fun `unlock rejects empty salt or device key`() {
        val v = vault()
        assertNull(v.unlock(passphrase, "", deviceKey))
        assertNull(v.unlock(passphrase, "33".repeat(32), ""))
    }

    @Test
    fun `a failing deriver is reported as a failed unlock, not a crash`() {
        val failing = object : KeyDeriver {
            override fun newSalt() = "00".repeat(32)
            override fun newRouteKey() = "00".repeat(32)
            override fun deriveVaultKey(
                passphrase: String,
                saltHex: String,
                deviceKeyHex: String,
                profile: String,
            ): String = throw IllegalStateException("protocol core exploded")
        }

        assertNull(Vault(failing).unlock(passphrase, "33".repeat(32), deviceKey))
    }

    @Test
    fun `destroy zeroes both key halves`() {
        val created = vault().create(passphrase, deviceKey)
        val key = created.key

        key.destroy()

        assertTrue(key.cipherKey.all { it == 0.toByte() })
        assertTrue(key.macKey.all { it == 0.toByte() })
    }

    @Test
    fun `the default profile is balanced`() {
        val deriver = FakeKeyDeriver()
        Vault(deriver).create(passphrase, deviceKey)

        assertEquals(VaultProfile.BALANCED, deriver.lastProfile)
    }

    @Test
    fun `the requested profile is forwarded to the core`() {
        val deriver = FakeKeyDeriver()
        Vault(deriver).create(passphrase, deviceKey, VaultProfile.HIGH)

        assertEquals(VaultProfile.HIGH, deriver.lastProfile)
    }

    @Test
    fun `a vault key of the wrong length is rejected rather than silently truncated`() {
        val short = object : KeyDeriver {
            override fun newSalt() = "00".repeat(32)
            override fun newRouteKey() = "00".repeat(32)
            override fun deriveVaultKey(
                passphrase: String,
                saltHex: String,
                deviceKeyHex: String,
                profile: String,
            ): String = "ab".repeat(32) // 32 bytes, not 64
        }

        // create() throws because the core returned the wrong size; unlock() turns
        // any failure into null.
        assertNull(Vault(short).unlock(passphrase, "33".repeat(32), deviceKey))
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
