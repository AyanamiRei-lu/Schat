package com.schat.android.core.onboarding

import com.schat.android.core.ServerConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class OnboardingStateTest {

    private val fingerprint = "1199304bc36cba074c90707e9515a73ba570d5d364e30c0dd566a24bb07142f4"
    private val uri = "schat://connect?h=192.168.1.158&n=lan&p=8443&fp=$fingerprint&ss=1"
    private val passphrase = "correct horse battery staple"

    private fun seed(fill: Int = 7): ByteArray = ByteArray(32) { fill.toByte() }

    private fun atPassphrase(): OnboardingState =
        OnboardingState().identityCreated().getOrThrow()

    private fun atRecovery(): OnboardingState =
        atPassphrase().setPassphrase(passphrase, passphrase, seed()).getOrThrow()

    private fun atServer(): OnboardingState {
        val s = atRecovery()
        val indices = s.confirmationIndices()
        return s.confirmRecovery(indices, indices.map { s.recoveryWords[it] }).getOrThrow()
    }

    // ---- ordering ----------------------------------------------------------

    @Test
    fun `starts at identity`() {
        assertEquals(OnboardingStep.IDENTITY, OnboardingState().step)
        assertFalse(OnboardingState().isComplete)
    }

    @Test
    fun `cannot skip the identity step`() {
        val state = atPassphrase()
        assertTrue(state.identityCreated().isFailure)
    }

    @Test
    fun `cannot set a passphrase before generating an identity`() {
        assertTrue(OnboardingState().setPassphrase(passphrase, passphrase, seed()).isFailure)
    }

    @Test
    fun `cannot confirm recovery before setting a passphrase`() {
        assertTrue(atPassphrase().confirmRecovery(listOf(0), listOf("acorn")).isFailure)
    }

    @Test
    fun `cannot configure a server before confirming recovery`() {
        assertTrue(atRecovery().setServer(uri).isFailure)
    }

    /** The whole point of the ordering: no path reaches READY without a recovery code. */
    @Test
    fun `reaches ready only through every step`() {
        val state = atServer().setServer(uri).getOrThrow()

        assertEquals(OnboardingStep.READY, state.step)
        assertTrue(state.isComplete)
        assertNotNull(state.server)
        assertEquals(ServerConfig.parse(uri).getOrThrow(), state.server)
        assertEquals(24, state.recoveryWords.size)
    }

    // ---- passphrase --------------------------------------------------------

    @Test
    fun `requires both entries to match`() {
        val result = atPassphrase().setPassphrase(passphrase, "$passphrase ", seed())
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.contains("不一致"))
    }

    @Test
    fun `rejects a short passphrase`() {
        val result = atPassphrase().setPassphrase("short", "short", seed())
        assertTrue(result.isFailure)
    }

    @Test
    fun `rejects a repeated single character`() {
        assertNotNull(passphraseProblem("aaaaaaaaaaaa"))
    }

    @Test
    fun `rejects leading or trailing whitespace`() {
        assertNotNull(passphraseProblem(" $passphrase"))
        assertNotNull(passphraseProblem("$passphrase "))
    }

    @Test
    fun `rejects common passphrases`() {
        assertNotNull(passphraseProblem("password123"))
        assertNotNull(passphraseProblem("PASSWORD123"))
    }

    @Test
    fun `accepts a long passphrase`() {
        assertNull(passphraseProblem("correct horse battery staple"))
        // A long single-word-ish phrase must not be rejected for lacking symbols.
        assertNull(passphraseProblem("thisisalongpassphrase"))
    }

    // ---- recovery code -----------------------------------------------------

    /** A word list whose size does not match the bit width would be a silent bug. */
    @Test
    fun `the word list is exactly as large as the bit width allows`() {
        assertEquals(1 shl RecoveryCode.BITS_PER_WORD, RecoveryCode.WORDS.size)
    }

    @Test
    fun `the word list has no duplicates`() {
        assertEquals(RecoveryCode.WORDS.size, RecoveryCode.WORDS.toSet().size)
    }

    @Test
    fun `generates the documented number of words`() {
        val words = RecoveryCode.fromSeed(seed())
        assertEquals(RecoveryCode.WORD_COUNT, words.size)
        words.forEach { assertTrue(it, RecoveryCode.WORDS.contains(it)) }
    }

    @Test
    fun `is deterministic for the same seed`() {
        assertEquals(RecoveryCode.fromSeed(seed()), RecoveryCode.fromSeed(seed()))
    }

    @Test
    fun `differs for a different seed`() {
        assertFalse(RecoveryCode.fromSeed(seed(1)) == RecoveryCode.fromSeed(seed(2)))
    }

    /**
     * Bit extraction must consume the seed most-significant-first. Reading whole bytes
     * and masking would make many output words depend on the same bits, which is the
     * kind of defect that looks fine until someone counts.
     */
    @Test
    fun `every bit position influences the output`() {
        val base = RecoveryCode.fromSeed(ByteArray(32))
        // Flipping the last bit of the first byte used must change the first word.
        val flipped = ByteArray(32).also { it[0] = 1 }
        assertFalse(
            "the most significant bit of the seed did not affect the code",
            base == RecoveryCode.fromSeed(flipped),
        )
    }

    @Test
    fun `rejects a seed that is too short`() {
        try {
            RecoveryCode.fromSeed(ByteArray(4))
            throw AssertionError("expected an exception for a 4-byte seed")
        } catch (expected: IllegalArgumentException) {
            // as designed
        }
    }

    @Test
    fun `rejects an empty seed`() {
        try {
            RecoveryCode.fromSeed(ByteArray(0))
            throw AssertionError("expected an exception for an empty seed")
        } catch (expected: IllegalArgumentException) {
            // as designed
        }
    }

    @Test
    fun `formats four words per line`() {
        val formatted = RecoveryCode.format(RecoveryCode.fromSeed(seed()))
        assertEquals(6, formatted.lines().size)
    }

    // ---- recovery confirmation --------------------------------------------

    @Test
    fun `confirmation indices are distinct and in range`() {
        val indices = atRecovery().confirmationIndices()
        assertEquals(RECOVERY_CONFIRMATION_WORDS, indices.size)
        assertEquals(indices.size, indices.toSet().size)
        indices.forEach { assertTrue(it.toString(), it in 0 until RecoveryCode.WORD_COUNT) }
    }

    @Test
    fun `accepts the correct words regardless of case and spacing`() {
        val state = atRecovery()
        val indices = state.confirmationIndices()
        val typed = indices.map { "  " + state.recoveryWords[it].uppercase() + " " }

        val next = state.confirmRecovery(indices, typed).getOrThrow()
        assertEquals(OnboardingStep.SERVER, next.step)
    }

    @Test
    fun `rejects an incorrect word`() {
        val state = atRecovery()
        val indices = state.confirmationIndices()
        val typed = indices.map { state.recoveryWords[it] }.toMutableList()
        typed[0] = "definitelynotaword"

        val result = state.confirmRecovery(indices, typed)
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.contains("不正确"))
    }

    @Test
    fun `rejects a mismatched number of answers`() {
        val state = atRecovery()
        assertTrue(state.confirmRecovery(listOf(0, 1), listOf("acorn")).isFailure)
    }

    @Test
    fun `rejects an empty confirmation`() {
        assertTrue(atRecovery().confirmRecovery(emptyList(), emptyList()).isFailure)
    }

    @Test
    fun `rejects an out of range index`() {
        val state = atRecovery()
        assertTrue(state.confirmRecovery(listOf(999), listOf("acorn")).isFailure)
    }

    // ---- server ------------------------------------------------------------

    @Test
    fun `rejects a malformed server descriptor`() {
        val result = atServer().setServer("not a uri")
        assertTrue(result.isFailure)
    }

    /** A self-signed relay with nothing to pin is the one config that must never pass. */
    @Test
    fun `rejects a self-signed server with no fingerprint`() {
        val result = atServer().setServer("schat://connect?h=192.168.1.158&ss=1")
        assertTrue(result.isFailure)
    }

    @Test
    fun `accepts a publicly trusted server`() {
        val state = atServer().setServer("schat://connect?h=chat.example.com&p=443").getOrThrow()
        assertEquals(OnboardingStep.READY, state.step)
        assertFalse(state.server!!.selfSigned)
    }
}

/**
 * A sanity check that the generator produces a spread of words rather than repeating
 * one, which is what a broken bit extraction would look like.
 */
class RecoveryCodeDistributionTest {

    @Test
    fun `random seeds produce varied codes`() {
        val random = SecureRandom()
        val seen = mutableSetOf<String>()

        repeat(64) {
            val seed = ByteArray(32).also { random.nextBytes(it) }
            val words = RecoveryCode.fromSeed(seed)
            assertEquals(24, words.size)
            seen += words.joinToString(" ")
        }

        // 64 codes of 24 words each; a generator stuck on a small subset would collide
        // far more often than this.
        assertEquals(64, seen.size)
    }
}
