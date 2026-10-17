package com.schat.android.core.recovery

import com.schat.android.core.onboarding.RecoveryCode
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Tests for the recovery backup.
 *
 * They are the only automated check this feature will ever get: the UI around it can be
 * compiled but not run without a device, so the crypto has to be provably right here.
 */
class RecoveryBackupTest {

    private val words = RecoveryCode.WORDS.take(RecoveryCode.WORD_COUNT)
    private val payload = ProfileBackupCodec.encode(
        ProfileBackup(
            identityJson = """{"ed25519":"00ff","x25519":"11ee"}""",
            routeKeyHex = "ab".repeat(32),
            recoveryCode = RecoveryCode.format(words),
            serverUri = "schat://connect?h=192.168.1.10&p=8443&n=relay&ss=1&fp=" + "cd".repeat(32),
            contacts = emptyList(),
        ),
    )

    // ------------------------------------------------------------------ 种子

    @Test
    fun `toSeed inverts fromSeed`() {
        val seed = ByteArray(21) { (it * 7 + 3).toByte() }
        val rendered = RecoveryCode.fromSeed(seed)

        val recovered = RecoveryBackup.toSeed(rendered)

        assertArrayEquals(seed, recovered)
    }

    @Test
    fun `toSeed accepts upper case and surrounding space`() {
        val shouted = words.map { "  ${it.uppercase()} " }

        assertArrayEquals(RecoveryBackup.toSeed(words), RecoveryBackup.toSeed(shouted))
    }

    @Test
    fun `toSeed accepts a unique prefix`() {
        // The word list guarantees the first three letters are distinct, which is what
        // makes a partially legible handwritten code resolvable.
        val prefix = words[0].take(3)
        val mangled = words.toMutableList().also { it[0] = prefix }

        assertArrayEquals(RecoveryBackup.toSeed(words), RecoveryBackup.toSeed(mangled))
    }

    @Test
    fun `toSeed rejects a word that is not in the list`() {
        val bad = words.toMutableList().also { it[5] = "zzzznotaword" }

        try {
            RecoveryBackup.toSeed(bad)
            fail("expected a rejection")
        } catch (e: RecoveryBackupException) {
            assertTrue("message should name the position: ${e.message}", e.message!!.contains("第 6 个词"))
        }
    }

    @Test
    fun `toSeed rejects the wrong number of words`() {
        try {
            RecoveryBackup.toSeed(words.take(23))
            fail("expected a rejection")
        } catch (e: RecoveryBackupException) {
            assertTrue(e.message!!.contains("24"))
        }
    }

    // ------------------------------------------------------------------ 信封

    @Test
    fun `seal then open round trips`() {
        val envelope = RecoveryBackup.seal(payload, words)

        assertEquals(payload, RecoveryBackup.open(envelope, words))
    }

    @Test
    fun `sealing twice produces different ciphertext`() {
        // A fresh salt and IV each time: two backups of the same profile must not look
        // identical, or comparing two exports would leak whether the profile changed.
        assertNotEquals(RecoveryBackup.seal(payload, words), RecoveryBackup.seal(payload, words))
    }

    @Test
    fun `open with the wrong words fails`() {
        val envelope = RecoveryBackup.seal(payload, words)
        val other = RecoveryCode.fromSeed(ByteArray(21) { 9 })

        try {
            RecoveryBackup.open(envelope, other)
            fail("expected a rejection")
        } catch (e: RecoveryBackupException) {
            assertTrue(e.message!!.contains("不匹配"))
        }
    }

    @Test
    fun `open rejects a tampered body`() {
        val envelope = RecoveryBackup.seal(payload, words)
        val lines = envelope.trim().split('\n').toMutableList()
        val blobLine = lines.indexOfFirst { it.startsWith("blob=") }
        val blob = lines[blobLine].removePrefix("blob=").toCharArray()
        blob[blob.size / 2] = if (blob[blob.size / 2] == 'A') 'B' else 'A'
        lines[blobLine] = "blob=" + String(blob)

        try {
            RecoveryBackup.open(lines.joinToString("\n"), words)
            fail("expected a rejection")
        } catch (e: RecoveryBackupException) {
            assertTrue(e.message!!.contains("不匹配") || e.message!!.contains("Base64"))
        }
    }

    @Test
    fun `open rejects a foreign document`() {
        try {
            RecoveryBackup.open("hello world", words)
            fail("expected a rejection")
        } catch (e: RecoveryBackupException) {
            assertTrue(e.message!!.contains("备份"))
        }
    }

    @Test
    fun `open rejects a swapped salt`() {
        // The header is authenticated, so replacing the salt cannot silently derive a
        // different key and "succeed".
        val envelope = RecoveryBackup.seal(payload, words)
        val tampered = envelope.replace(
            Regex("salt=[0-9a-f]+"),
            "salt=" + "11".repeat(32),
        )

        try {
            RecoveryBackup.open(tampered, words)
            fail("expected a rejection")
        } catch (e: RecoveryBackupException) {
            assertTrue(e.message!!.contains("不匹配"))
        }
    }

    // -------------------------------------------------------------------- HKDF

    @Test
    fun `hkdf matches RFC 5869 case 1`() {
        // Without a published vector, a hand-written HKDF is only "probably fine".
        val ikm = ByteArray(22) { 0x0b }
        val salt = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
        val info = byteArrayOf(
            0xf0.toByte(), 0xf1.toByte(), 0xf2.toByte(), 0xf3.toByte(), 0xf4.toByte(),
            0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(), 0xf8.toByte(), 0xf9.toByte(),
        )

        val okm = hkdfSha256(ikm, salt, info, 42)

        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865",
            okm.joinToString("") { "%02x".format(it) },
        )
    }
}
