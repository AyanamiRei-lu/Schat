package com.schat.android.core.names

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 名字簿：身份 → 对方自报的昵称。
 *
 * 它是联系人之外的第二个名字来源，因为群里可能有人从未与你建立过一对一会话——
 * 那些人不在联系人里，但你仍然要看到他们在群里叫什么。
 */
class PeerNamesTest {

    private val a = "aa".repeat(32)
    private val b = "bb".repeat(32)

    @Test
    fun `names survive an encode-decode round trip`() {
        val names = mapOf(a to "阿狸", b to "Bob")
        assertEquals(names, PeerNames.decode(PeerNames.encode(names)))
    }

    @Test
    fun `a hostile name cannot forge a second record`() {
        // 名字是对方给的输入。行格式里一个换行就能变出第二条记录——base64 编码掉分隔符，
        // 清洗再去掉控制字符；两件事都必须发生，缺一件就有一条伪造记录。
        val hostile = "x\n$b\ty"
        val decoded = PeerNames.decode(PeerNames.encode(mapOf(a to hostile)))

        assertEquals(1, decoded.size)
        assertEquals(
            com.schat.android.core.contacts.ContactCodec.sanitiseNickname(hostile),
            decoded[a],
        )
        assertFalse("the injected identity became a record", decoded.containsKey(b))
    }

    @Test
    fun `a corrupt line is skipped and the rest survives`() {
        val encoded = PeerNames.encode(mapOf(a to "阿狸")) +
            "not-an-identity\tQQ==\n" +
            "$b\tnot-base64!\n" +
            "\n"

        val decoded = PeerNames.decode(encoded)

        assertEquals(mapOf(a to "阿狸"), decoded)
    }

    @Test
    fun `a foreign document is refused`() {
        assertEquals(emptyMap<String, String>(), PeerNames.decode("SOMETHING-ELSE\n"))
        assertEquals(emptyMap<String, String>(), PeerNames.decode(""))
    }

    @Test
    fun `the book is bounded`() {
        val many = (1..PeerNames.MAX_ENTRIES + 30).associate {
            "%064x".format(it) to "n$it"
        }
        val encoded = PeerNames.encode(many)
        assertEquals(PeerNames.MAX_ENTRIES, encoded.lines().count { it.isNotBlank() } - 1)
        assertEquals(PeerNames.MAX_ENTRIES, PeerNames.decode(encoded).size)
    }

    @Test
    fun `the last write wins`() {
        var names = PeerNames.put(emptyMap(), a, "旧名字")
        names = PeerNames.put(names, a, "新名字")
        assertEquals("新名字", names[a])
    }

    @Test
    fun `an empty name clears the entry`() {
        var names = PeerNames.put(emptyMap(), a, "阿狸")
        names = PeerNames.put(names, a, "")
        assertFalse(names.containsKey(a))
    }

    @Test
    fun `a malformed identity is never remembered`() {
        assertTrue(PeerNames.put(emptyMap(), "not-a-key", "阿狸").isEmpty())
        // 大小写不同但格式合法：归一化成小写，与联系人那边的键保持一致，而不是拒绝。
        assertEquals("阿狸", PeerNames.put(emptyMap(), a.uppercase(), "阿狸")[a])
    }
}
