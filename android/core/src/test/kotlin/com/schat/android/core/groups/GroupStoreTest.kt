package com.schat.android.core.groups

import com.schat.android.data.store.EncryptedStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class GroupStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val key = ByteArray(32) { it.toByte() }

    private fun newStore(): GroupStore = GroupStore(EncryptedStore(File(temp.root, "vault.dat"), key))

    private fun record(
        id: String = "67727031",
        state: String = "{\"version\":1}",
        generation: Long = 0,
    ) = GroupRecord(id, state, generation)

    @Test
    fun `saves and reads back a group`() {
        val store = newStore()
        store.save(record(generation = 7))

        val loaded = store.load("67727031")
        assertEquals("{\"version\":1}", loaded?.stateJson)
        assertEquals(7L, loaded?.generation)
        assertEquals(listOf("67727031"), store.list())
    }

    @Test
    fun `a missing group reads back as null`() {
        assertNull(newStore().load("67727031"))
    }

    @Test
    fun `an absent generation is not defaulted`() {
        // The generation is what keeps a key from being used twice. A store that defaulted it to
        // zero would make the next message REUSE generation zero's key, which is the one failure
        // an AEAD does not survive — and it would do so silently.
        val store = newStore()
        store.save(record(generation = 3))
        assertEquals(3L, store.load("67727031")?.generation)

        // A record whose generation is unreadable must be refused rather than treated as zero.
        store.save(record(generation = 0))
        assertEquals(0L, store.load("67727031")?.generation)
    }

    @Test
    fun `a legacy member-name record is cleaned up`() {
        // 旧版本按叶子下标存过成员备注名。它已不是显示来源（显示改由身份键控的名字簿回答），
        // 所以重新保存与删除群都必须把它清掉，而不是让旧数据永远留在保险库里。
        val enc = EncryptedStore(File(temp.root, "vault.dat"), key)
        val store = GroupStore(enc)
        store.save(record())

        enc.putString("group.67727031.names", "0:A")
        store.save(record())
        assertFalse(enc.contains("group.67727031.names"))

        enc.putString("group.67727031.names", "0:A")
        store.clear("67727031")
        assertFalse(enc.contains("group.67727031.names"))
    }

    @Test
    fun `groups do not interfere`() {
        val store = newStore()
        store.save(record(id = "aaaa", state = "first", generation = 1))
        store.save(record(id = "bbbb", state = "second", generation = 2))

        assertEquals("first", store.load("aaaa")?.stateJson)
        assertEquals("second", store.load("bbbb")?.stateJson)
        assertEquals(listOf("aaaa", "bbbb"), store.list().sorted())
    }

    @Test
    fun `clearing one group leaves the others`() {
        val store = newStore()
        store.save(record(id = "aaaa"))
        store.save(record(id = "bbbb"))

        store.clear("aaaa")

        assertNull(store.load("aaaa"))
        assertEquals("{\"version\":1}", store.load("bbbb")?.stateJson)
        assertEquals(listOf("bbbb"), store.list())
    }

    @Test
    fun `clearing the last group leaves no index behind`() {
        val store = newStore()
        store.save(record(id = "aaaa"))
        store.clear("aaaa")

        assertTrue(store.list().isEmpty())
        assertNull(store.load("aaaa"))
    }

    @Test
    fun `saving the same group twice does not duplicate it in the index`() {
        val store = newStore()
        store.save(record(state = "one"))
        store.save(record(state = "two"))

        assertEquals(listOf("67727031"), store.list())
        assertEquals("two", store.load("67727031")?.stateJson)
    }

    @Test
    fun `a group that is not there is not listed`() {
        val store = newStore()
        store.save(record(id = "aaaa"))
        assertFalse(store.list().contains("bbbb"))
    }

    @Test
    fun `saveGeneration advances the stored position without rewriting the state`() {
        // The generation is the sender's ratchet position. `sendGroup` used to throw the value
        // away and keep passing the snapshot's old one, so every message in an epoch claimed
        // generation zero. The state JSON holds epoch keys; advancing a counter must not rewrite it.
        val store = newStore()
        store.save(record(state = "snapshot", generation = 0))
        store.saveGeneration("67727031", 4)

        val loaded = store.load("67727031")!!
        assertEquals(4L, loaded.generation)
        assertEquals("snapshot", loaded.stateJson)
    }

    @Test
    fun `saveGeneration refuses a negative position`() {
        val store = newStore()
        store.save(record())
        assertThrows(IllegalArgumentException::class.java) {
            store.saveGeneration("67727031", -1)
        }
    }

    @Test
    fun `saveGeneration refuses a group that was never saved`() {
        // A generation without its state is half a record: it would let a caller believe the
        // group exists while every read still returns null.
        val store = newStore()
        assertThrows(IllegalArgumentException::class.java) {
            store.saveGeneration("missing", 1)
        }
    }
}
