package com.schat.android.data.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * 明文键值存储的行为。
 *
 * # 为什么它值得一套自己的测试
 *
 * 它服务的是一类**特定时机**的记录：必须在保险库建立之前就能写入的那些。如果它坏了，
 * 症状是"用户同意过协议，但下次启动又回到条款页"——一个看起来像 UI 问题的存储问题。
 *
 * 而它比 [EncryptedStore] 更容易写坏，因为它自己要处理编码：键用 base64、值也用
 * base64，而这一点必须被证明，而不是被假设——协议版本记录里会出现中文与换行，
 * 一个只按 `\t` 与 `\n` 切分的实现会在那里悄悄丢数据。
 */
class PlainFileStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun newStore(name: String = "plain.txt"): PlainFileStore =
        PlainFileStore(File(temp.root, name))

    @Test
    fun `a missing key reads back as null`() {
        assertNull(newStore().getString("nothing"))
    }

    @Test
    fun `a value survives a write and a read`() {
        val store = newStore()
        store.putString("legal.consent.version.user-agreement", "1.0")
        assertEquals("1.0", store.getString("legal.consent.version.user-agreement"))
    }

    @Test
    fun `values containing newlines tabs and chinese survive`() {
        // 这是这个类最容易写坏的地方：如果值没有编码就直接写进行格式，
        // 一个含换行的值会把文件切成两行，读回来就不是原来那个值了。
        val store = newStore()
        val value = "第一行\n第二行\t带制表符\n版本：1.0"
        store.putString("k", value)
        assertEquals(value, store.getString("k"))
    }

    @Test
    fun `keys containing separators survive`() {
        val store = newStore()
        val key = "a\tb\nc 键"
        store.putString(key, "v")
        assertEquals("v", store.getString(key))
    }

    @Test
    fun `a record survives reopening the file`() {
        // "重启应用"的模型：换一个实例读同一个文件。
        newStore().putString("legal.consent.at", "1700000000000")
        assertEquals("1700000000000", newStore().getString("legal.consent.at"))
    }

    @Test
    fun `writing the same key replaces the value`() {
        val store = newStore()
        store.putString("k", "old")
        store.putString("k", "new")
        assertEquals("new", store.getString("k"))
    }

    @Test
    fun `remove reports whether it removed anything`() {
        val store = newStore()
        store.putString("k", "v")
        assertTrue(store.remove("k"))
        assertFalse("删第二次应该返回 false", store.remove("k"))
        assertNull(store.getString("k"))
    }

    @Test
    fun `contains and names reflect what is stored`() {
        val store = newStore()
        store.putString("a", "1")
        store.putString("b", "2")
        assertTrue(store.contains("a"))
        assertFalse(store.contains("c"))
        assertEquals(setOf("a", "b"), store.names())
    }

    @Test
    fun `an empty name is refused`() {
        var threw = false
        try {
            newStore().putString("", "v")
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun `a foreign or corrupt file is ignored rather than half parsed`() {
        val file = File(temp.root, "plain.txt")
        file.writeText("这不是我们的格式\nsome\tjunk\n")

        val store = PlainFileStore(file)
        assertNull("不认得的文件应当被整个忽略", store.getString("some"))
        assertEquals(0, store.names().size)

        // 而它仍然可用：写进去的东西读得回来
        store.putString("k", "v")
        assertEquals("v", store.getString("k"))
    }

    @Test
    fun `clearing removes the file and everything in it`() {
        val file = File(temp.root, "plain.txt")
        val store = PlainFileStore(file)
        store.putString("k", "v")
        assertTrue(file.exists())

        store.clear()
        assertFalse(file.exists())
        assertNull(store.getString("k"))
    }

    @Test
    fun `the file is written with our magic so a foreign file is not merged into it`() {
        val file = File(temp.root, "plain.txt")
        PlainFileStore(file).putString("k", "v")
        assertEquals("SCHAT-PLAIN-1", file.readLines().first())
    }
}
