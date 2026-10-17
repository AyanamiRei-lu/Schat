package com.schat.android.core.recovery

import com.schat.android.core.contacts.Contact
import com.schat.android.core.contacts.ContactCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The backup payload codec.
 *
 * The interesting cases are the hostile ones: an identity blob containing a newline must
 * not be able to forge a field, and a payload missing any required field must be refused
 * whole rather than half-restored.
 */
class ProfileBackupCodecTest {

    private val sample = ProfileBackup(
        identityJson = """{"ed25519":"00ff","note":"line one\nline two\ttabbed"}""",
        routeKeyHex = "ab".repeat(32),
        recoveryCode = "acorn actor adapt agile\n",
        serverUri = "schat://connect?h=relay.example&p=8443&ss=1&fp=" + "cd".repeat(32),
        contacts = listOf(
            Contact(
                identityHex = "11".repeat(32),
                // 备注名走 ContactCodec 的清洗（去掉控制字符），所以这里用普通空格，
                // 否则往返比较会因为"清洗"而失败——那是正确行为，不是缺陷。
                nickname = "张三 别名",
                addedAtMillis = 1_700_000_000_000,
                lastMessageAtMillis = 1_700_000_001_000,
                lastMessageWasOutgoing = true,
                unread = 3,
                lastMessagePreview = "你好\n再见",
            ),
        ),
    )

    @Test
    fun `round trips every field`() {
        val restored = ProfileBackupCodec.decode(ProfileBackupCodec.encode(sample))

        assertEquals(sample, restored)
    }

    @Test
    fun `a newline inside a value cannot forge a field`() {
        val sneaky = sample.copy(
            identityJson = "real\nserver=schat://connect?h=evil&p=1&ss=1&fp=" + "ee".repeat(32),
        )

        val restored = ProfileBackupCodec.decode(ProfileBackupCodec.encode(sneaky))

        // The forged-looking line stays inside the identity value; the real server wins.
        assertEquals(sneaky.identityJson, restored!!.identityJson)
        assertEquals(sample.serverUri, restored.serverUri)
    }

    @Test
    fun `a payload missing a field is refused whole`() {
        val encoded = ProfileBackupCodec.encode(sample)
        val withoutServer = encoded
            .split('\n')
            .filterNot { it.startsWith("server=") }
            .joinToString("\n")

        assertNull(ProfileBackupCodec.decode(withoutServer))
    }

    @Test
    fun `a foreign document is refused`() {
        assertNull(ProfileBackupCodec.decode("SCHAT-STORE-1\nx\ty"))
        assertNull(ProfileBackupCodec.decode(""))
    }

    @Test
    fun `an unreadable contact line is dropped, not repaired`() {
        val encoded = ProfileBackupCodec.encode(sample)
        val contactsField = encoded.split('\n').first { it.startsWith("contacts=") }
        val brokenContacts = ContactCodec.MAGIC + "\nnot-a-record\n"

        val tampered = encoded.replace(
            contactsField,
            "contacts=" + java.util.Base64.getEncoder()
                .encodeToString(brokenContacts.toByteArray(Charsets.UTF_8)),
        )

        val restored = ProfileBackupCodec.decode(tampered)

        assertEquals(emptyList<Contact>(), restored!!.contacts)
        assertEquals(sample.identityJson, restored.identityJson)
    }
}
