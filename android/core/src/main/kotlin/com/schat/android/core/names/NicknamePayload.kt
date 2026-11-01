package com.schat.android.core.names

import com.schat.android.core.contacts.ContactCodec
import java.util.Base64

/**
 * 昵称通告的线载荷。
 *
 * # 格式
 *
 * ```
 * SCHAT-NICK-1\n<base64(昵称 UTF-8)>
 * ```
 *
 * Base64 不是美化，是防注入：昵称是对方给的输入，而它的上一站/下一站是行格式的存储。
 * 换行与制表符在这里被编码掉，于是任何名字都无法变出第二条记录。
 *
 * # 两种「坏」
 *
 * - 认不出来（版本不对、base64 坏、超长）→ `null`，调用方丢弃。
 * - 认出来但是空的 → `""`，表示「清除」：对方回退到身份缩写。
 *
 * 这两种必须分开：把「清除」当成坏包会让用户改不回原来的名字，而把坏包当成「清除」
 * 会让一个字节错误静默地抹掉名字。
 */
object NicknamePayload {

    const val MAGIC = "SCHAT-NICK-1"

    /**
     * 整段载荷的上限。
     *
     * 推导：昵称上限 64 个 UTF-16 单元，最坏是每个单元 3 字节的 UTF-8（192 字节），
     * base64 后 256 字符，加上 `SCHAT-NICK-1\n` 的 13 字节 = 269。取 320 留余量。
     * 写成 256 会让解码拒绝自己刚编码出来的合法昵称。
     */
    const val MAX_WIRE_BYTES = 320

    /** 编码。清洗规则与联系人备注一致——它是同一个用户在同一个输入框里会打的东西。 */
    fun encode(raw: String): ByteArray {
        val clean = ContactCodec.sanitiseNickname(raw)
        val encoded = Base64.getEncoder().encodeToString(clean.toByteArray(Charsets.UTF_8))
        return (MAGIC + "\n" + encoded).toByteArray(Charsets.UTF_8)
    }

    /** 解码；`null` 表示这不是本版本能理解的昵称通告。 */
    fun decode(bytes: ByteArray): String? {
        if (bytes.isEmpty() || bytes.size > MAX_WIRE_BYTES) return null

        val text = String(bytes, Charsets.UTF_8)
        val separator = text.indexOf('\n')
        if (separator <= 0) return null
        if (text.substring(0, separator) != MAGIC) return null

        val raw = try {
            String(Base64.getDecoder().decode(text.substring(separator + 1).trim()), Charsets.UTF_8)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return ContactCodec.sanitiseNickname(raw)
    }
}
