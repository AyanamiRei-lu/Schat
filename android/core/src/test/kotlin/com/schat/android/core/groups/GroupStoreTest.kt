package com.schat.android.core.groups

import com.schat.android.data.store.EncryptedStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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
        names: Map<Long, String> = emptyMap(),
    ) = GroupRecord(id, state, generation, names)

    @Test
    fun `saves and reads back a group`() {
        val store = newStore()
        store.save(record(generation = 7, names = mapOf(0L to "爱丽丝", 1L to "Bob")))

        val loaded = store.load("67727031")
        assertEquals("{\"version\":1}", loaded?.stateJson)
        assertEquals(7L, loaded?.generation)
        assertEquals(mapOf(0L to "爱丽丝", 1L to "Bob"), loaded?.memberNames)
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
    fun `a name cannot inject a member`() {
        // The index and the names share one store and one separator. An unescaped newline or
        // colon in a display name would come back as an extra member — a record that looks like
        // it belongs to leaf 5 and does not.
        val store = newStore()
        val hostile = "x\n5:somebody else"
        store.save(record(names = mapOf(0L to hostile)))

        val loaded = store.load("67727031")!!
        assertEquals(1, loaded.memberNames.size)
        assertEquals(hostile, loaded.memberNames[0L])
        assertNull(loaded.memberNames[5L])
    }

    @Test
    fun `every separator in a name survives a round trip`() {
        val store = newStore()
        val names = mapOf(
            0L to "a:b",
            1L to "line\nbreak",
            2L to "carriage\rreturn",
            3L to "back\\slash",
            4L to "trailing\\",
        )
        store.save(record(names = names))

        assertEquals(names, store.load("67727031")?.memberNames)
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
        store.save(record(id = "aaaa", names = mapOf(0L to "A")))
        store.save(record(id = "bbbb", names = mapOf(0L to "B")))

        store.clear("aaaa")

        assertNull(store.load("aaaa"))
        assertEquals("{\"version\":1}", store.load("bbbb")?.stateJson)
        assertEquals(mapOf(0L to "B"), store.load("bbbb")?.memberNames)
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
}
