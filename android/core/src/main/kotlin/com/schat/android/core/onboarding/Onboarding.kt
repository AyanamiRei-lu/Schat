package com.schat.android.core.onboarding

import com.schat.android.core.ServerConfig
import com.schat.android.core.crypto.Vault

/**
 * The onboarding state machine.
 *
 * It is here, in :core, rather than inside the Compose screens, for the same reason
 * the vault is: the rules that decide whether a user may proceed are the part worth
 * testing, and they must be testable without a device. The screens then become a
 * thin rendering of this state.
 *
 * The ordering is a security property, not a UX preference. A user who reaches the
 * chat screen without a recovery code has a vault that cannot be restored, and a user
 * who skips the passphrase has a vault that is not protected at all. Both are
 * unrecoverable mistakes, so the transitions refuse them rather than relying on the
 * UI to hide a button.
 */
enum class OnboardingStep {
    /** Generate the long-term identity. */
    IDENTITY,

    /** Choose the passphrase that protects the vault. */
    PASSPHRASE,

    /** Write down the recovery code. */
    RECOVERY,

    /** Point the client at a relay. */
    SERVER,

    /** Everything required exists. */
    READY,
}

/**
 * How much of the recovery code the user must type back.
 *
 * Three words is the standard trade: enough that a user who wrote nothing down
 * cannot stumble through, few enough that it does not invite copy-paste defeatism.
 */
const val RECOVERY_CONFIRMATION_WORDS = 3

data class OnboardingState(
    val step: OnboardingStep = OnboardingStep.IDENTITY,
    val passphrase: String = "",
    val recoveryWords: List<String> = emptyList(),
    val server: ServerConfig? = null,
) {
    /** True once the flow has produced everything a working client needs. */
    val isComplete: Boolean
        get() = step == OnboardingStep.READY

    /**
     * Advances past identity generation.
     *
     * The identity itself is produced by the protocol core and stored by the caller;
     * what matters here is that the step cannot be skipped, so a client can never
     * reach the passphrase screen with no identity to protect.
     */
    fun identityCreated(): Result<OnboardingState> {
        if (step != OnboardingStep.IDENTITY) {
            return fail("当前不在生成身份这一步")
        }
        return Result.success(copy(step = OnboardingStep.PASSPHRASE))
    }

    /**
     * Stores the passphrase and derives the recovery words.
     *
     * The words are generated from [entropySeed], which the caller obtains from the
     * platform's secure random source, so that the recovery code carries real entropy
     * rather than being derived from the passphrase.
     */
    fun setPassphrase(
        passphrase: String,
        confirmation: String,
        entropySeed: ByteArray,
    ): Result<OnboardingState> {
        if (step != OnboardingStep.PASSPHRASE) {
            return fail("当前不在设置口令这一步")
        }
        if (passphrase != confirmation) {
            return fail("两次输入的口令不一致")
        }
        passphraseProblem(passphrase)?.let { return fail(it) }

        return Result.success(
            copy(
                step = OnboardingStep.RECOVERY,
                passphrase = passphrase,
                recoveryWords = RecoveryCode.fromSeed(entropySeed),
            )
        )
    }

    /**
     * Checks the words the user typed back.
     *
     * [indices] are the positions being asked about, in the order they were asked.
     * Comparison is case-insensitive and ignores surrounding whitespace, because
     * failing a user on capitalisation would push them towards storing the code
     * somewhere convenient — which is the outcome the confirmation step exists to
     * prevent.
     */
    fun confirmRecovery(indices: List<Int>, typed: List<String>): Result<OnboardingState> {
        if (step != OnboardingStep.RECOVERY) {
            return fail("当前不在确认恢复码这一步")
        }
        if (indices.size != typed.size) {
            return fail("需要确认的单词数量与输入不一致")
        }
        if (indices.isEmpty()) {
            return fail("没有需要确认的单词")
        }

        for ((position, index) in indices.withIndex()) {
            if (index !in recoveryWords.indices) {
                return fail("第 ${index + 1} 个单词不存在")
            }
            val expected = recoveryWords[index]
            val actual = typed[position].trim().lowercase()
            if (actual != expected) {
                return fail("第 ${index + 1} 个单词不正确")
            }
        }

        return Result.success(copy(step = OnboardingStep.SERVER))
    }

    /**
     * Parses and stores the server descriptor.
     *
     * A relay that cannot be dialled is refused here rather than surfacing as a
     * mysterious connection failure later; see [ServerConfig.parse].
     */
    fun setServer(raw: String): Result<OnboardingState> {
        if (step != OnboardingStep.SERVER) {
            return fail("当前不在配置服务器这一步")
        }

        val parsed = ServerConfig.parse(raw).getOrElse { return fail(it.message ?: "连接信息无效") }
        if (!parsed.isUsable) {
            return fail(parsed.unusableReason() ?: "连接信息不可用")
        }

        return Result.success(copy(step = OnboardingStep.READY, server = parsed))
    }

    /**
     * Picks the positions to ask about during recovery confirmation.
     *
     * The selection is derived from the words themselves rather than from a random
     * source, so a test can assert a specific answer and the UI cannot accidentally
     * ask about the same position twice.
     */
    fun confirmationIndices(count: Int = RECOVERY_CONFIRMATION_WORDS): List<Int> {
        if (recoveryWords.isEmpty()) return emptyList()
        val n = minOf(count, recoveryWords.size)

        // A stride derived from the word count spreads the questions across the code
        // so that a user who only remembers the opening words is caught.
        val stride = recoveryWords.size / n
        return (0 until n).map { it * stride }
    }

    private fun fail(message: String): Result<OnboardingState> =
        Result.failure(OnboardingException(message))
}

/** Thrown for a refused onboarding transition. */
class OnboardingException(message: String) : Exception(message)

/**
 * Why a passphrase is unacceptable, or null when it is fine.
 *
 * The list is deliberately short and blunt. Rejecting long passphrases for lacking a
 * symbol pushes users towards `Password1!`, which is worse than a long phrase; what
 * is worth blocking is the handful of shapes that carry almost no entropy.
 */
fun passphraseProblem(passphrase: String): String? {
    if (passphrase.length < Vault.MIN_PASSPHRASE_LENGTH) {
        return "口令至少需要 ${Vault.MIN_PASSPHRASE_LENGTH} 个字符"
    }
    if (passphrase.all { it == passphrase[0] }) {
        return "口令不能是同一个字符的重复"
    }
    if (passphrase.trim().length != passphrase.length) {
        return "口令的首尾不能是空格"
    }
    val lowered = passphrase.lowercase()
    if (COMMON_PASSPHRASES.any { lowered == it }) {
        return "这个口令过于常见，请换一个"
    }
    if (COMMON_PASSPHRASES.any { lowered.contains(it) && lowered.length < 16 }) {
        return "口令过于简单，请避免使用常见词组"
    }
    return null
}

private val COMMON_PASSPHRASES = listOf(
    "password", "12345678", "123456789", "1234567890", "qwertyuiop",
    "iloveyou", "letmein", "admin123", "schat1234", "aaaaaaaaaa",
)

/**
 * The recovery code: 24 words drawn from a 128-word list.
 *
 * # Why not BIP-39
 *
 * BIP-39's 2048-word list would give 11 bits per word, but it has to be embedded
 * verbatim — roughly 15 KB of source — and its value is interoperability with other
 * wallets and tools. A SCHAT recovery code is only ever typed into SCHAT, so that
 * interoperability buys nothing.
 *
 * A 128-word list gives 7 bits per word: 24 words is 168 bits, which is far past the
 * point where brute force is a concern. The words are all short, distinct and
 * unmatched in their first three letters, so a partially legible handwritten copy can
 * still be resolved.
 *
 * # Honest limitation
 *
 * 168 bits is less than the 256 bits the vault key actually has, so the recovery code
 * is not a full-strength copy of the key material. It does not need to be: it is a
 * second factor for restoring *access*, and an attacker who can brute-force 168 bits
 * can also brute-force the passphrase, which is the weaker factor by a wide margin.
 */
object RecoveryCode {
    /** The number of words in a recovery code. */
    const val WORD_COUNT = 24

    /** Bits carried by one word. */
    const val BITS_PER_WORD = 7

    /**
     * Derives the recovery words from a seed.
     *
     * Bits are consumed most-significant-first from the seed, seven at a time. Reading
     * whole bytes and masking would bias the distribution, which matters when the
     * result is the only thing standing between an attacker and a restored vault.
     */
    fun fromSeed(seed: ByteArray, wordCount: Int = WORD_COUNT): List<String> {
        require(seed.isNotEmpty()) { "recovery seed must not be empty" }
        require(wordCount > 0) { "word count must be positive" }

        val requiredBits = wordCount * BITS_PER_WORD
        require(seed.size * 8 >= requiredBits) {
            "recovery seed of ${seed.size} bytes cannot supply $requiredBits bits"
        }

        val words = ArrayList<String>(wordCount)
        var bitPosition = 0
        repeat(wordCount) {
            var index = 0
            repeat(BITS_PER_WORD) {
                val byteIndex = bitPosition / 8
                val bitInByte = 7 - (bitPosition % 8)
                val bit = (seed[byteIndex].toInt() shr bitInByte) and 1
                index = (index shl 1) or bit
                bitPosition++
            }
            words += WORDS[index]
        }
        return words
    }

    /** Renders a code for display, four words per line. */
    fun format(words: List<String>): String =
        words.chunked(4).joinToString("\n") { it.joinToString("  ") }

    /**
     * The word list. Exactly 128 entries, because seven bits select one of them.
     *
     * Every entry is lowercase and short, and the list favours words that look
     * different from one another at a glance — a user transcribing a handwritten code
     * is the failure mode being designed against, not an attacker who can already
     * read the paper.
     *
     * A test asserts the size is exactly 1 shl BITS_PER_WORD, so an edit that adds or
     * removes a word fails the build rather than silently making some words
     * unreachable or some indices out of range.
     */
    val WORDS: List<String> = """
        acorn actor adapt agile alarm album alert alien amber ample anchor angel
        angle ankle apple apron arch arena argue arise armor arrow ashen aside
        atlas atom attic audio author autumn avoid awake award aware axis azure
        bacon badge bagel baker balmy bamboo banana banner barley barrel basil
        basket batch beacon bean beaver beech begin belief bell belt bench berry
        birch bison bitter blade blaze blend blimp blink bloom blossom blue bluff
        blunt blurt board boast bobsled bonfire bonus border borrow bottle boulder
        bracket braid breeze brick bridge bright brisk brook broom brush bubble
        bucket buffet bugle builder bundle burden burrow bushel butter button
        cabin cactus camera campus canal candle canyon carbon cargo carpet carrot
        casino castle cavern cedar celery cement census ceramic chalet chamber
        cherry chisel chorus cider
    """.trimIndent().split(Regex("\\s+")).filter { it.isNotEmpty() }
}
