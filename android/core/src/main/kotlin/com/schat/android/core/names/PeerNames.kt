package com.schat.android.core.names

import com.schat.android.core.contacts.ContactCodec
import java.util.Base64

/**
 * 名字簿：身份公钥 → 对方自报的昵称。
 *
 * # 为什么不是联系人
 *
 * 联系人只包含「聊过的人」。群成员可能是别人拉进来的，你从未与他建立过一对一会话，
 * 而他仍然要显示一个名字。名字簿按**身份**索引而不是按群里的叶子下标——下标每次成员
 * 变更都会变，身份不会。
 *
 * # 格式
 *
 * ```
 * SCHAT-PEERS-1
 * <identityHex>\t<base64(昵称)>
 * ```
 *
 * 与联系人编码一样是行格式 + Base64：昵称是输入，行分隔符必须不可能出现在它里面。
 * 坏行被跳过而不是让整本失效——一条读不懂的名字不该让其余名字一起消失。
 */
object PeerNames {

    const val MAGIC = "SCHAT-PEERS-1"

    /** 上限。与联系人列表同量级：超过它的部分不可能被显示。 */
    const val MAX_ENTRIES = 500

    fun encode(names: Map<String, String>): String {
        val builder = StringBuilder(MAGIC).append('\n')
        var written = 0
        for ((identity, name) in names) {
            if (written >= MAX_ENTRIES) break
            if (!ContactCodec.isIdentity(identity)) continue
            builder
                .append(identity).append('\t')
                .append(Base64.getEncoder().encodeToString(name.toByteArray(Charsets.UTF_8)))
                .append('\n')
            written += 1
        }
        return builder.toString()
    }

    fun decode(text: String): Map<String, String> {
        val lines = text.split('\n')
        if (lines.firstOrNull()?.trim() != MAGIC) return emptyMap()

        val out = LinkedHashMap<String, String>()
        for (line in lines.drop(1)) {
            if (line.isBlank()) continue
            if (out.size >= MAX_ENTRIES) break

            val parts = line.split('\t')
            if (parts.size != 2) continue

            val identity = parts[0].trim().lowercase()
            if (!ContactCodec.isIdentity(identity)) continue

            val name = decodeText(parts[1]) ?: continue
            out[identity] = ContactCodec.sanitiseNickname(name)
        }
        return out
    }

    /**
     * 写入一条名字，返回新的映射。
     *
     * 身份先归一化成小写：联系人那边也是这么做的，两处的键必须能对上。
     * 空名字表示**删除**这一条，而不是存一个空串——否则「清除」与「从未听说」在显示上
     * 一样，在存储里却越积越多。
     */
    fun put(names: Map<String, String>, identityHex: String, name: String): Map<String, String> {
        val identity = identityHex.trim().lowercase()
        if (!ContactCodec.isIdentity(identity)) return names

        val clean = ContactCodec.sanitiseNickname(name)
        val out = LinkedHashMap(names)
        if (clean.isEmpty()) out.remove(identity) else out[identity] = clean
        return out
    }

    private fun decodeText(value: String): String? = try {
        String(Base64.getDecoder().decode(value.trim()), Charsets.UTF_8)
    } catch (e: IllegalArgumentException) {
        null
    }
}
