package com.schat.android.core.recovery

import com.schat.android.core.contacts.Contact
import com.schat.android.core.contacts.ContactCodec
import java.util.Base64

/**
 * What a recovery backup carries.
 *
 * # 为什么是这几项，而不是整个档案
 *
 * 备份的目的只有一个：**换一台设备之后，还能用同一个身份继续收发消息**。
 * 做到这件事需要的东西恰好是 `identityJson`（身份密钥对）、`serverUri`（中继地址）与
 * `recoveryCode`（让用户知道手上这份码仍然有效）。`routeKeyHex` 一并带上，省得新设备
 * 换一个投递路由、让对方看到"换了个人"。
 *
 * **预密钥池刻意不在备份里。** 一次性预密钥只能用一次，旧设备上被消费掉的那些如果原样
 * 带到新设备并重新发布，同一个预密钥会被发放两次——那正是预密钥池要防止的事。恢复时
 * 用身份重新生成一池新的（见 `AppWiring`），是唯一正确的做法。
 *
 * **联系人随备份走**，因为它们是本机的记录，不走就等于换机之后把好友全丢了。聊天记录
 * 不随备份走：那些消息用旧会话的密钥加密，新设备没有对应的棘轮状态，带过去也读不出来。
 */
data class ProfileBackup(
    /** The identity key pair, as produced by the protocol core. */
    val identityJson: String,

    /** The delivery route key, hex. */
    val routeKeyHex: String,

    /** The recovery code, formatted for display. */
    val recoveryCode: String,

    /** The relay this client is pointed at, as a `schat://` URI. */
    val serverUri: String,

    /** Locally remembered peers. */
    val contacts: List<Contact> = emptyList(),
)

/**
 * Serialises [ProfileBackup] for inclusion in an encrypted backup.
 *
 * # Why not JSON here
 *
 * Same reason as [ContactCodec] and `EncryptedStore`: `org.json` exists on Android but
 * throws on a plain JVM, and this module's tests run on a plain JVM. A line-oriented
 * format with Base64 fields is unambiguous — an identity blob containing a newline or a
 * tab cannot forge an extra field, because every value is Base64 first.
 *
 * # Format
 *
 * ```
 * SCHAT-PROFILE-1
 * identity=<base64>
 * route=<base64>
 * recovery=<base64>
 * server=<base64>
 * contacts=<base64 of a ContactCodec document>
 * ```
 */
object ProfileBackupCodec {

    const val MAGIC = "SCHAT-PROFILE-1"

    fun encode(backup: ProfileBackup): String = buildString {
        append(MAGIC).append('\n')
        append("identity=").append(enc(backup.identityJson)).append('\n')
        append("route=").append(enc(backup.routeKeyHex)).append('\n')
        append("recovery=").append(enc(backup.recoveryCode)).append('\n')
        append("server=").append(enc(backup.serverUri)).append('\n')
        append("contacts=").append(enc(ContactCodec.encode(backup.contacts))).append('\n')
    }

    /**
     * Parses a backup payload, or returns null.
     *
     * A payload missing any field is rejected whole rather than partially restored: an
     * identity without its server address, or without the rest of the record, would
     * produce a client that looks restored and is not.
     */
    fun decode(text: String): ProfileBackup? {
        val lines = text.split('\n')
        if (lines.firstOrNull()?.trim() != MAGIC) return null

        val fields = HashMap<String, String>()
        for (line in lines.drop(1)) {
            if (line.isBlank()) continue
            val eq = line.indexOf('=')
            if (eq <= 0) continue
            fields[line.substring(0, eq).trim()] = line.substring(eq + 1)
        }

        val identity = fields["identity"]?.let(::dec) ?: return null
        val route = fields["route"]?.let(::dec) ?: return null
        val recovery = fields["recovery"]?.let(::dec) ?: return null
        val server = fields["server"]?.let(::dec) ?: return null
        val contactsText = fields["contacts"]?.let(::dec) ?: return null

        if (identity.isBlank() || server.isBlank()) return null

        return ProfileBackup(
            identityJson = identity,
            routeKeyHex = route,
            recoveryCode = recovery,
            serverUri = server,
            contacts = ContactCodec.decode(contactsText),
        )
    }

    private fun enc(value: String): String =
        Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))

    private fun dec(value: String): String? = try {
        String(Base64.getDecoder().decode(value.trim()), Charsets.UTF_8)
    } catch (e: IllegalArgumentException) {
        null
    }
}
