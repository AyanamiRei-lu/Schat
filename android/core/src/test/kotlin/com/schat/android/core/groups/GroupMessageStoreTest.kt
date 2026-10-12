package com.schat.android.core.groups

import com.schat.android.data.store.EncryptedStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class GroupMessageStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val key = ByteArray(32) { it.toByte() }

    private fun newStore(): GroupStore = GroupStore(EncryptedStore(File(temp.root, "vault.dat"), key))

    private fun message(text: String, leaf: Long = 0, mine: Boolean = false, at: Long = 1L) =
        GroupMessage(fromLeaf = leaf, mine = mine, generation = 0, atMillis = at, text = text)

    private fun readyStore(): GroupStore = newStore().apply {
        save(GroupRecord("67727031", "{\"version\":1}", 0))
    }

    @Test
    fun `appends and reads messages in order`() {
        val store = readyStore()
        store.appendMessage("67727031", message("第一条", at = 1))
        store.appendMessage("67727031", message("第二条", at = 2, leaf = 1))

        val loaded = store.loadMessages("67727031")
        assertEquals(2, loaded.size)
        assertEquals("第一条", loaded[0].text)
        assertEquals("第二条", loaded[1].text)
        assertEquals(1L, loaded[1].fromLeaf)
    }

    @Test
    fun `a message body cannot fabricate another message`() {
        // The same shape of attack as a display name containing a separator: the history is one
        // string with one separator, so a body that can inject it becomes a record that nobody
        // sent. This is the assertion that keeps the encoding honest.
        val store = readyStore()
        val hostile = "hello|9|0|999|a message from nobody"
        store.appendMessage("67727031", message(hostile))

        val loaded = store.loadMessages("67727031")
        assertEquals(1, loaded.size)
        assertEquals(hostile, loaded[0].text)
        assertEquals(0L, loaded[0].fromLeaf)
    }

    @Test
    fun `a newline in a body does not split it`() {
        val store = readyStore()
        val hostile = "first line\nsecond line"
        store.appendMessage("67727031", message(hostile))

        val loaded = store.loadMessages("67727031")
        assertEquals(1, loaded.size)
        assertEquals(hostile, loaded[0].text)
    }

    @Test
    fun `the history is capped and keeps the newest`() {
        val store = readyStore()
        repeat(GROUP_MESSAGE_LIMIT + 5) { index ->
            store.appendMessage("67727031", message("m$index", at = index.toLong()))
        }

        val loaded = store.loadMessages("67727031")
        assertEquals(GROUP_MESSAGE_LIMIT, loaded.size)
        // The OLDEST are the ones dropped: a history that discarded the newest would lose the
        // conversation the user is having.
        assertEquals("m5", loaded.first().text)
        assertEquals("m${GROUP_MESSAGE_LIMIT + 4}", loaded.last().text)
    }

    @Test
    fun `clearing a group clears its messages`() {
        // Deleting a group has to delete what was said in it. Leaving the history behind would
        // make the deletion a label rather than an act.
        val store = readyStore()
        store.appendMessage("67727031", message("秘密"))
        assertEquals(1, store.loadMessages("67727031").size)

        store.clear("67727031")

        assertTrue(store.loadMessages("67727031").isEmpty())
        assertEquals(null, store.load("67727031"))
    }

    @Test
    fun `messages of different groups do not mix`() {
        val store = newStore()
        store.save(GroupRecord("aaaa", "{}", 0))
        store.save(GroupRecord("bbbb", "{}", 0))

        store.appendMessage("aaaa", message("for a"))
        store.appendMessage("bbbb", message("for b"))

        assertEquals("for a", store.loadMessages("aaaa").single().text)
        assertEquals("for b", store.loadMessages("bbbb").single().text)
    }
}
