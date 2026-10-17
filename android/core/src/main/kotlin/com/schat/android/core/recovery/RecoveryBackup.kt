package com.schat.android.core.recovery

import com.schat.android.core.onboarding.RecoveryCode
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Raised for every reason a recovery code or backup cannot be used. Carries a user-facing message. */
class RecoveryBackupException(message: String) : Exception(message)

/**
 * 用恢复码加密/解密一份档案备份。
 *
 * # 为什么恢复码必须配上"备份"，而不是单独就能恢复
 *
 * 恢复码的 24 个词是**独立于保险库的随机熵**：保险库密钥由口令 + 设备密钥派生，恢复码
 * 从来没有参与过派生。所以单独 24 个词在数学上无法还原一个与它无关的 256 位密钥——任何声称
 * 只凭这 24 个词就能恢复的实现在骗人。
 *
 * 这里的做法是标准的那一种：**恢复码当密钥，备份当密文**。导出时用恢复码派生一把对称密钥，
 * 把身份档案加密成一段文本；换机时把这段文本粘过去，再输入 24 个词，就能解回身份。
 * 恢复码是唯一需要抄在纸上的东西，备份文本可以放在任何地方——它离开恢复码就是一堆密文。
 *
 * # 密钥派生
 *
 * `HKDF-SHA256(seed, salt, "schat-recovery-backup-v1")`，其中 `seed` 是 24 个词还原出的
 * 168 位种子，`salt` 每次导出重新随机。HKDF 在本模块用 `javax.crypto.Mac` 实现，
 * 有 RFC 5869 测试向量固定——不引入 Go 绑定重编，也不自创原语。
 *
 * 加密是 AES-256-GCM（12 字节 IV、128 位 tag），并把**头部一起作为附加认证数据**：
 * 改掉版本号或 salt 都会让解密失败，而不是悄悄用错 salt 派出一把错误的钥匙。
 *
 * # 词表匹配
 *
 * 输入容忍大小写与前后空格，并支持**唯一前缀匹配**（词表保证前三个字母互不相同）。
 * 手抄的码少认一两个字母是很现实的情况，而"对不上就整串拒绝"只会让人放弃这份备份。
 */
object RecoveryBackup {

    /** Envelope magic. Bumping it invalidates every older backup by design. */
    const val MAGIC = "SCHAT-BACKUP-1"

    private const val INFO = "schat-recovery-backup-v1"
    private const val SALT_BYTES = 32
    private const val KEY_BYTES = 32
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private val SECURE_RANDOM = SecureRandom()

    /**
     * 24 个词 → 168 位种子。
     *
     * 这是 [RecoveryCode.fromSeed] 的逆运算：按 7 位一组、从高位开始装填，与生成时完全
     * 相同的顺序，所以 `toSeed(fromSeed(x)) == x`。
     */
    fun toSeed(words: List<String>): ByteArray {
        if (words.size != RecoveryCode.WORD_COUNT) {
            throw RecoveryBackupException("恢复码需要 ${RecoveryCode.WORD_COUNT} 个单词，当前是 ${words.size} 个")
        }

        val bits = IntArray(words.size * RecoveryCode.BITS_PER_WORD)
        var cursor = 0
        for ((position, raw) in words.withIndex()) {
            val index = indexOf(raw, position)
            for (shift in RecoveryCode.BITS_PER_WORD - 1 downTo 0) {
                bits[cursor++] = (index shr shift) and 1
            }
        }

        check(cursor % 8 == 0) { "recovery seed is not byte aligned" }
        val out = ByteArray(cursor / 8)
        for (byte in out.indices) {
            var value = 0
            for (bit in 0 until 8) {
                value = (value shl 1) or bits[byte * 8 + bit]
            }
            out[byte] = value.toByte()
        }
        return out
    }

    /** Encrypts [plaintext] under a key derived from [words]. */
    fun seal(plaintext: String, words: List<String>): String {
        val seed = toSeed(words)
        val salt = ByteArray(SALT_BYTES).also(SECURE_RANDOM::nextBytes)
        val key = hkdfSha256(seed, salt, INFO.toByteArray(Charsets.UTF_8), KEY_BYTES)
        seed.fill(0)

        val iv = ByteArray(IV_BYTES).also(SECURE_RANDOM::nextBytes)
        val saltHex = hex(salt)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(associatedData(saltHex))
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        key.fill(0)

        return buildString {
            append(MAGIC).append('\n')
            append("salt=").append(saltHex).append('\n')
            append("blob=").append(Base64.getEncoder().encodeToString(iv + ciphertext)).append('\n')
        }
    }

    /** Decrypts an envelope produced by [seal]. Throws [RecoveryBackupException] on any mismatch. */
    fun open(envelope: String, words: List<String>): String {
        val lines = envelope.trim().split('\n')
        if (lines.firstOrNull()?.trim() != MAGIC) {
            throw RecoveryBackupException("这不是 SCHAT 的备份文本")
        }

        var saltHex: String? = null
        var blob: String? = null
        for (line in lines.drop(1)) {
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            when (line.substring(0, eq).trim()) {
                "salt" -> saltHex = line.substring(eq + 1).trim()
                "blob" -> blob = line.substring(eq + 1).trim()
            }
        }
        val salt = saltHex ?: throw RecoveryBackupException("备份缺少 salt 字段")
        val body = blob ?: throw RecoveryBackupException("备份缺少正文")

        val raw = try {
            Base64.getDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            throw RecoveryBackupException("备份正文不是合法的 Base64")
        }
        if (raw.size < IV_BYTES + TAG_BITS / 8) {
            throw RecoveryBackupException("备份正文不完整")
        }

        val iv = raw.copyOfRange(0, IV_BYTES)
        val ciphertext = raw.copyOfRange(IV_BYTES, raw.size)

        val seed = toSeed(words)
        val key = hkdfSha256(seed, hexToBytes(salt), INFO.toByteArray(Charsets.UTF_8), KEY_BYTES)
        seed.fill(0)

        val plaintext = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(associatedData(salt))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // GCM 的 tag 校验失败只有两种可能：恢复码不对，或备份被改过。
            // 从密码学上区分不了这两种，所以话就说到这里，不再猜。
            throw RecoveryBackupException("恢复码与备份不匹配，或备份已损坏")
        } finally {
            key.fill(0)
        }

        return String(plaintext, Charsets.UTF_8)
    }

    // ------------------------------------------------------------------

    private fun associatedData(saltHex: String): ByteArray =
        "$MAGIC\n$saltHex".toByteArray(Charsets.UTF_8)

    /**
     * Finds the index of [raw] in the word list.
     *
     * Exact match first, then a unique prefix match. A prefix matching more than one word
     * is refused rather than guessed: guessing would restore the wrong key, which is
     * indistinguishable from "the words are wrong" to the user.
     */
    private fun indexOf(raw: String, position: Int): Int {
        val word = raw.trim().lowercase()
        if (word.isEmpty()) {
            throw RecoveryBackupException("第 ${position + 1} 个词是空的")
        }

        val exact = RecoveryCode.WORDS.indexOf(word)
        if (exact >= 0) return exact

        val candidates = RecoveryCode.WORDS.withIndex().filter { it.value.startsWith(word) }
        return when (candidates.size) {
            1 -> candidates[0].index
            0 -> throw RecoveryBackupException("第 ${position + 1} 个词不在词表里：\"$word\"")
            else -> throw RecoveryBackupException(
                "第 ${position + 1} 个词有多种可能的拼写：\"$word\"，请写全",
            )
        }
    }
}

/**
 * HKDF-SHA256（RFC 5869）。
 *
 * `internal` 而不是私有，是为了让 `:core` 的测试能拿 RFC 5869 的向量固定它——
 * 一段自己写的派生代码如果不被向量固定住，它"看起来对"就只是看起来。
 */
internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length > 0) { "hkdf length must be positive" }
    require(length <= 255 * 32) { "hkdf length out of range" }

    val mac = Mac.getInstance("HmacSHA256")

    // Extract
    mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
    val prk = mac.doFinal(ikm)

    // Expand
    mac.init(SecretKeySpec(prk, "HmacSHA256"))
    val out = ByteArray(length)
    var block = ByteArray(0)
    var offset = 0
    var counter = 1
    while (offset < length) {
        mac.reset()
        mac.update(block)
        mac.update(info)
        mac.update(counter.toByte())
        block = mac.doFinal()

        val take = minOf(block.size, length - offset)
        System.arraycopy(block, 0, out, offset, take)
        offset += take
        counter++
    }
    return out
}

private fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
    for (b in bytes) append("%02x".format(b))
}

private fun hexToBytes(hex: String): ByteArray {
    if (hex.length % 2 != 0) throw RecoveryBackupException("备份里的 salt 长度不合法")
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(hex[i * 2], 16)
        val lo = Character.digit(hex[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) throw RecoveryBackupException("备份里的 salt 不是十六进制")
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
