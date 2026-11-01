package com.schat.android.core.names

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 昵称通告的载荷格式。
 *
 * 它同时出现在两条加密通道里（单聊 SCS-1 帧、群 MLS 私密消息），所以解析必须对
 * **任何字节**都只做两件事：认出来，或者拒绝。绝不猜。
 */
class NicknamePayloadTest {

    @Test
    fun `round trips a chinese nickname`() {
        assertEquals("阿狸", NicknamePayload.decode(NicknamePayload.encode("阿狸")))
    }

    @Test
    fun `an empty nickname means clear`() {
        // 清除是一个合法动作：对方会回退到身份缩写，而不是保留旧名字。
        assertEquals("", NicknamePayload.decode(NicknamePayload.encode("")))
    }

    @Test
    fun `rejects a payload with an unknown version`() {
        assertNull(NicknamePayload.decode("SCHAT-NAME-9\nQQ==".toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun `rejects invalid base64`() {
        assertNull(NicknamePayload.decode((NicknamePayload.MAGIC + "\n!!!").toByteArray()))
    }

    @Test
    fun `rejects a payload over the wire bound`() {
        val oversized = NicknamePayload.MAGIC + "\n" + "A".repeat(NicknamePayload.MAX_WIRE_BYTES)
        assertNull(NicknamePayload.decode(oversized.toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun `strips control characters before they reach a line format`() {
        assertEquals("ab", NicknamePayload.decode(NicknamePayload.encode("a\nb")))
    }

    @Test
    fun `caps a nickname at the shared limit`() {
        val long = "x".repeat(500)
        assertEquals(
            com.schat.android.core.contacts.ContactCodec.MAX_NICKNAME_LENGTH,
            NicknamePayload.decode(NicknamePayload.encode(long))?.length,
        )
    }

    @Test
    fun `a nickname at the character limit is not rejected by our own wire bound`() {
        // 64 个三字节字符 -> 192 字节 UTF-8 -> base64 256 字符，再加 magic 行 13 字节 = 269。
        // 上限若还是 256，编码能产出、解码会拒绝——自己拒绝自己。
        val longest = "阿".repeat(com.schat.android.core.contacts.ContactCodec.MAX_NICKNAME_LENGTH)
        assertEquals(longest, NicknamePayload.decode(NicknamePayload.encode(longest)))
    }
}
