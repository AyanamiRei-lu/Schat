package com.schat.android.core.contacts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The contact list: serialisation and the rules that decide what the user sees.
 *
 * These run on the JVM, which is the point of putting them in `:core` — the alternative was
 * to have them reachable only through a device.
 */
class ContactCodecTest {

    private val a = "aa".repeat(32)
    private val b = "bb".repeat(32)

    private fun sample(identity: String = a) = Contact(
        identityHex = identity,
        nickname = "Alice",
        addedAtMillis = 1_700_000_000_000,
        lastMessageAtMillis = 1_700_000_500_000,
        lastMessagePreview = "see you at 8",
        lastMessageWasOutgoing = true,
        unread = 3,
    )

    @Test
    fun `a contact survives an encode-decode round trip`() {
        val decoded = ContactCodec.decode(ContactCodec.encode(listOf(sample(), sample(b))))

        assertEquals(2, decoded.size)
        assertEquals(sample(), decoded[0])
    }

    @Test
    fun `the file is tagged so a foreign file is not half-read`() {
        assertTrue(ContactCodec.encode(listOf(sample())).startsWith(ContactCodec.MAGIC))
        assertEquals(emptyList<Contact>(), ContactCodec.decode("SOMETHING-ELSE\n${a}\t"))
        assertEquals(emptyList<Contact>(), ContactCodec.decode(""))
    }

    @Test
    fun `a nickname cannot forge an extra record`() {
        // A nickname is user input, and a newline or a tab inside it would otherwise be
        // able to break the line-oriented format and inject a second contact.
        val hostile = sample().copy(
            nickname = "Mallory\n$b\t" + "cc".repeat(32) + "\t0\t0\t0\t0\tAAAA",
        )

        val decoded = ContactCodec.decode(ContactCodec.encode(listOf(hostile)))

        assertEquals("the nickname created a second record", 1, decoded.size)
        assertEquals("the injected identity was accepted", a, decoded[0].identityHex)
        assertFalse(
            "control characters survived into the nickname",
            decoded[0].nickname.any { it.isISOControl() },
        )
    }

    @Test
    fun `a damaged record is dropped without taking the good ones with it`() {
        val good = ContactCodec.encode(listOf(sample()))
        val damaged = good +
            "not-an-identity\tQQ==\t0\t0\t0\t0\tQQ==\n" +      // bad identity
            "$b\tQQ==\t0\t0\t0\t0\n" +                          // too few fields
            "$b\tnot-base64!\t0\t0\t0\t0\tQQ==\n"               // undecodable nickname

        val decoded = ContactCodec.decode(damaged)

        assertEquals(1, decoded.size)
        assertEquals(a, decoded[0].identityHex)
    }

    @Test
    fun `a timestamp that is not a number does not lose the contact`() {
        val line = ContactCodec.encode(listOf(sample())).lines()[1].split('\t').toMutableList()
        line[2] = "yesterday"
        line[3] = ""

        val decoded = ContactCodec.decode("${ContactCodec.MAGIC}\n" + line.joinToString("\t"))

        assertEquals(1, decoded.size)
        assertEquals(0L, decoded[0].addedAtMillis)
        assertEquals(0L, decoded[0].lastMessageAtMillis)
    }

    @Test
    fun `an identity is normalised to lowercase`() {
        val decoded = ContactCodec.decode(
            ContactCodec.encode(listOf(sample(a.uppercase()))),
        )
        assertEquals(a, decoded[0].identityHex)
    }

    @Test
    fun `the list is bounded in both directions`() {
        val many = (1..ContactCodec.MAX_CONTACTS + 50).map {
            Contact(identityHex = "%064x".format(it), addedAtMillis = it.toLong())
        }

        val encoded = ContactCodec.encode(many)
        assertEquals(
            "encoding accepted more contacts than the bound",
            ContactCodec.MAX_CONTACTS,
            encoded.lines().count { it.isNotBlank() } - 1,
        )

        // ...and a file that somehow holds more is bounded on the way in too.
        val forged = StringBuilder(ContactCodec.MAGIC).append('\n')
        repeat(ContactCodec.MAX_CONTACTS + 50) { i ->
            forged.append("%064x".format(i)).append("\tQQ==\t0\t0\t0\t0\tQQ==\n")
        }
        assertEquals(ContactCodec.MAX_CONTACTS, ContactCodec.decode(forged.toString()).size)
    }

    @Test
    fun `nicknames are cleaned and bounded`() {
        assertEquals("Alice", ContactCodec.sanitiseNickname("  Alice  "))
        assertEquals("Alice", ContactCodec.sanitiseNickname("Ali\u0000ce"))
        assertEquals("ab", ContactCodec.sanitiseNickname("a\nb"))
        assertEquals("", ContactCodec.sanitiseNickname("\n\t  "))

        val long = "x".repeat(500)
        assertEquals(ContactCodec.MAX_NICKNAME_LENGTH, ContactCodec.sanitiseNickname(long).length)
    }

    @Test
    fun `an unnamed contact shows an abbreviation of its key`() {
        val unnamed = Contact(identityHex = a)
        assertFalse(unnamed.isNamed)
        assertEquals("aaaaaaaa…aaaaaaaa", unnamed.displayName)

        val named = unnamed.copy(nickname = "Bob")
        assertTrue(named.isNamed)
        assertEquals("Bob", named.displayName)
    }
}

class ContactListTest {

    private val a = "aa".repeat(32)
    private val b = "bb".repeat(32)
    private val c = "cc".repeat(32)

    @Test
    fun `the most recent conversation is first`() {
        var list = emptyList<Contact>()
        list = ContactList.noteMessage(list, a, atMillis = 100, text = "one", outgoing = false)
        list = ContactList.noteMessage(list, b, atMillis = 300, text = "three", outgoing = false)
        list = ContactList.noteMessage(list, c, atMillis = 200, text = "two", outgoing = false)

        assertEquals(listOf(b, c, a), list.map { it.identityHex })
    }

    @Test
    fun `a contact with no messages is ordered by when it was added`() {
        // Adding someone and seeing them sink below every existing conversation reads as
        // "the add did not work".
        var list = ContactList.noteMessage(emptyList(), a, atMillis = 100, text = "hi", outgoing = false)
        list = ContactList.ensure(list, b, nowMillis = 500)

        assertEquals(listOf(b, a), list.map { it.identityHex })
    }

    @Test
    fun `the order is stable when two contacts share a timestamp`() {
        var list = emptyList<Contact>()
        list = ContactList.noteMessage(list, b, 100, "x", outgoing = false)
        list = ContactList.noteMessage(list, a, 100, "x", outgoing = false)

        // Ties break on identity, so the list cannot reorder itself between two renders.
        assertEquals(listOf(a, b), list.map { it.identityHex })
        assertEquals(
            ContactList.sorted(list.map { it.copy() }),
            ContactList.sorted(list.reversed().map { it.copy() }),
        )
    }

    @Test
    fun `an incoming message raises a badge and an outgoing one does not`() {
        var list = ContactList.noteMessage(emptyList(), a, 100, "hello", outgoing = false)
        assertEquals(1, list[0].unread)

        list = ContactList.noteMessage(list, a, 200, "hello back", outgoing = true)
        assertEquals("a sent message must not badge the user's own inbox", 1, list[0].unread)
        assertEquals("hello back", list[0].lastMessagePreview)
        assertTrue(list[0].lastMessageWasOutgoing)

        list = ContactList.noteMessage(list, a, 300, "again", outgoing = false)
        assertEquals(2, list[0].unread)
        assertFalse(list[0].lastMessageWasOutgoing)
    }

    @Test
    fun `opening a conversation clears only its badge`() {
        var list = ContactList.noteMessage(emptyList(), a, 100, "x", outgoing = false)
        list = ContactList.noteMessage(list, b, 200, "y", outgoing = false)

        list = ContactList.markRead(list, a)

        assertEquals(0, list.first { it.identityHex == a }.unread)
        assertEquals(1, list.first { it.identityHex == b }.unread)
        assertEquals(1, ContactList.totalUnread(list))
    }

    @Test
    fun `an empty nickname never erases one the user set`() {
        // This is the common path, not a corner case: every re-established session upserts
        // a contact record that carries no nickname.
        var list = ContactList.rename(emptyList(), a, "Alice")
        list = ContactList.upsert(list, Contact(identityHex = a, addedAtMillis = 999))

        assertEquals("Alice", list[0].nickname)
        assertEquals(1, list.size)
    }

    @Test
    fun `merging keeps the earlier added time and the later activity`() {
        var list = ContactList.upsert(emptyList(), Contact(a, addedAtMillis = 100))
        list = ContactList.upsert(
            list,
            Contact(a, addedAtMillis = 900, lastMessageAtMillis = 500, lastMessagePreview = "later"),
        )

        assertEquals(100L, list[0].addedAtMillis)
        assertEquals(500L, list[0].lastMessageAtMillis)
        assertEquals("later", list[0].lastMessagePreview)
    }

    @Test
    fun `renaming cleans the input and an empty name clears it`() {
        var list = ContactList.ensure(emptyList(), a, 1)
        list = ContactList.rename(list, a, "  Ali\nce  ")
        assertEquals("Alice", list[0].nickname)

        list = ContactList.rename(list, a, "   ")
        assertEquals("", list[0].nickname)
        assertEquals("aaaaaaaa…aaaaaaaa", list[0].displayName)
    }

    @Test
    fun `naming an unknown identity creates the record instead of silently doing nothing`() {
        val list = ContactList.rename(emptyList(), a, "Alice")

        assertEquals(1, list.size)
        assertEquals(a, list[0].identityHex)
        assertEquals("Alice", list[0].nickname)
    }

    @Test
    fun `a malformed identity is never named into existence`() {
        assertTrue(ContactList.rename(emptyList(), "not-a-key", "Alice").isEmpty())
    }

    @Test
    fun `removing forgets exactly one contact`() {
        var list = ContactList.ensure(emptyList(), a, 1)
        list = ContactList.ensure(list, b, 2)
        list = ContactList.remove(list, a)

        assertEquals(listOf(b), list.map { it.identityHex })
    }

    @Test
    fun `only a well-formed identity becomes a contact`() {
        var list = ContactList.ensure(emptyList(), "not-a-key", 1)
        list = ContactList.ensure(list, a.dropLast(1), 1)
        list = ContactList.ensure(list, "zz".repeat(32), 1)
        assertTrue("a malformed identity was accepted", list.isEmpty())

        list = ContactList.ensure(list, a.uppercase(), 1)
        assertEquals(listOf(a), list.map { it.identityHex })

        // Idempotent: adding the same peer twice must not duplicate the row.
        list = ContactList.ensure(list, a, 2)
        assertEquals(1, list.size)
    }

    @Test
    fun `a preview is one line and bounded`() {
        assertEquals("hello world", ContactList.preview("  hello\n\nworld  "))
        assertEquals("a b", ContactList.preview("a\t\tb"))
        assertEquals("", ContactList.preview("   \n  "))
        assertEquals(
            ContactCodec.MAX_PREVIEW_LENGTH,
            ContactList.preview("x".repeat(5_000)).length,
        )
    }
}
