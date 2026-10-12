package com.schat.android.core.groups

import com.schat.android.data.store.EncryptedStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * 叶子私钥：64 个十六进制字符 = 32 字节。
 *
 * 它必须与 KeyPackage 一起保存：入群者用它解开寻址给自己的路径秘密。少了它，
 * 成员能进群却跟不上任何一条提交，而失败会出现在确认标签处——那里看不出原因。
 */
private const val TEST_LEAF_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

class MyKeyPackageTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val key = ByteArray(32) { it.toByte() }

    private fun newStore(): GroupStore = GroupStore(EncryptedStore(File(temp.root, "vault.dat"), key))

    @Test
    fun `saves and reads back all three values`() {
        val store = newStore()
        store.saveMyKeyPackage("aabb", "ccdd", TEST_LEAF_KEY)
        assertEquals(Triple("aabb", "ccdd", TEST_LEAF_KEY), store.loadMyKeyPackage())
    }

    @Test
    fun `a missing half reads back as null`() {
        // The init key is the only thing that opens a Welcome. A store that returned the
        // KeyPackage without it would let the client publish a membership it can never accept.
        val store = newStore()
        assertNull(store.loadMyKeyPackage())

        store.saveMyKeyPackage("aabb", "ccdd", TEST_LEAF_KEY)
        assertEquals("ccdd", store.loadMyKeyPackage()?.second)
    }

    @Test
    fun `saving again replaces the previous values`() {
        val store = newStore()
        store.saveMyKeyPackage("first", "one", TEST_LEAF_KEY)
        store.saveMyKeyPackage("second", "two", TEST_LEAF_KEY)
        assertEquals(Triple("second", "two", TEST_LEAF_KEY), store.loadMyKeyPackage())
    }

    @Test
    fun `empty halves are refused`() {
        val store = newStore()
        var threw = false
        try { store.saveMyKeyPackage("", "ccdd", TEST_LEAF_KEY) } catch (e: IllegalArgumentException) { threw = true }
        assertEquals(true, threw)
        assertNull(store.loadMyKeyPackage())
    }
}
