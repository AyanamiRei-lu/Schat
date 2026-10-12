package com.schat.android.core.contacts

/**
 * Operations on the contact list.
 *
 * # Why this is a separate object of pure functions
 *
 * Every one of these is a rule about what the user sees: which conversation is at the top,
 * whether a badge is showing, what a row of preview text says when the message was a
 * 4 000-character paragraph. Those rules are easier to get right — and possible to test —
 * when they are not entangled with a vault, a network thread and a ratchet.
 *
 * Nothing here reads a clock. Times are passed in, so a test can state an ordering rather
 * than hope for one.
 */
object ContactList {

    /**
     * Orders contacts for display: most recent activity first.
     *
     * A contact with no messages yet still has to appear, and appears by the time it was
     * added — otherwise adding someone would put them at the very bottom under every
     * conversation, which reads as "the add did not work".
     *
     * Ties break on the identity so the order is stable: a list that reorders itself
     * between two renders looks like a bug to the user.
     */
    fun sorted(contacts: List<Contact>): List<Contact> =
        contacts.sortedWith(
            compareByDescending<Contact> { activityOf(it) }
                .thenBy { it.identityHex },
        )

    /** Inserts [contact], or merges it into the existing record for the same identity. */
    fun upsert(contacts: List<Contact>, contact: Contact): List<Contact> {
        val identity = contact.identityHex.lowercase()
        val existing = contacts.firstOrNull { it.identityHex == identity }

        val merged = if (existing == null) {
            contact.copy(identityHex = identity)
        } else {
            existing.copy(
                // An empty incoming nickname must not erase one the user has set. That
                // happens whenever a session is (re)established for a contact already in
                // the list, which is the common case.
                nickname = contact.nickname.ifBlank { existing.nickname },
                addedAtMillis = if (existing.addedAtMillis == 0L) {
                    contact.addedAtMillis
                } else {
                    existing.addedAtMillis
                },
                lastMessageAtMillis = maxOf(existing.lastMessageAtMillis, contact.lastMessageAtMillis),
                lastMessagePreview = if (contact.lastMessageAtMillis >= existing.lastMessageAtMillis) {
                    contact.lastMessagePreview.ifBlank { existing.lastMessagePreview }
                } else {
                    existing.lastMessagePreview
                },
                lastMessageWasOutgoing = if (contact.lastMessageAtMillis >= existing.lastMessageAtMillis) {
                    contact.lastMessageWasOutgoing
                } else {
                    existing.lastMessageWasOutgoing
                },
                unread = maxOf(existing.unread, contact.unread),
            )
        }

        return sorted(contacts.filterNot { it.identityHex == identity } + merged)
    }

    /** Makes sure [identityHex] has a record, adding the peer of a new session. */
    fun ensure(contacts: List<Contact>, identityHex: String, nowMillis: Long): List<Contact> {
        val identity = identityHex.trim().lowercase()
        if (!ContactCodec.isIdentity(identity)) return contacts
        if (contacts.any { it.identityHex == identity }) return contacts
        return upsert(contacts, Contact(identityHex = identity, addedAtMillis = nowMillis))
    }

    /**
     * Sets the nickname for a contact, sanitising it. An empty nickname clears it.
     *
     * Naming an identity that is not in the list CREATES the record rather than doing
     * nothing. A silent no-op is the worse failure: the row would keep showing the old
     * name (or the raw key) and the user would conclude that the rename is broken, with
     * nothing on screen to suggest why. A visible extra row is self-explanatory.
     *
     * The created record carries no timestamp, so it sorts to the bottom until it is
     * talked to — which is where an unreachable name belongs.
     */
    fun rename(contacts: List<Contact>, identityHex: String, rawNickname: String): List<Contact> {
        val identity = identityHex.trim().lowercase()
        if (!ContactCodec.isIdentity(identity)) return contacts

        val clean = ContactCodec.sanitiseNickname(rawNickname)
        val withRecord = ensure(contacts, identity, nowMillis = 0)

        return sorted(
            withRecord.map {
                if (it.identityHex == identity) it.copy(nickname = clean) else it
            },
        )
    }

    /**
     * Forgets a contact.
     *
     * Only the record: the caller is responsible for the message history and the ratchet
     * snapshot, because those are stored under separate keys and deleting them is not
     * reversible. Leaving a snapshot behind would be harmless; leaving the history would
     * mean the conversation reappears if the peer writes again, which is why the caller
     * must decide.
     */
    fun remove(contacts: List<Contact>, identityHex: String): List<Contact> =
        contacts.filterNot { it.identityHex == identityHex.trim().lowercase() }

    /** Clears the unread badge, called when the conversation is opened. */
    fun markRead(contacts: List<Contact>, identityHex: String): List<Contact> {
        val identity = identityHex.trim().lowercase()
        return contacts.map {
            if (it.identityHex == identity && it.unread != 0) it.copy(unread = 0) else it
        }
    }

    /**
     * Records that a message was sent or received.
     *
     * A received message increments the badge; a sent one does not. Both update the
     * preview and the ordering, because "the last thing that happened in this
     * conversation" is what the list is showing.
     */
    fun noteMessage(
        contacts: List<Contact>,
        identityHex: String,
        atMillis: Long,
        text: String,
        outgoing: Boolean,
    ): List<Contact> {
        val identity = identityHex.trim().lowercase()
        val withRecord = ensure(contacts, identity, atMillis)

        return sorted(
            withRecord.map { contact ->
                if (contact.identityHex != identity) {
                    contact
                } else {
                    contact.copy(
                        lastMessageAtMillis = maxOf(contact.lastMessageAtMillis, atMillis),
                        lastMessagePreview = preview(text),
                        lastMessageWasOutgoing = outgoing,
                        unread = if (outgoing) contact.unread else contact.unread + 1,
                    )
                }
            },
        )
    }

    /** The number of unread messages across every conversation. */
    fun totalUnread(contacts: List<Contact>): Int = contacts.sumOf { it.unread }

    /**
     * Turns a message into one line of preview text.
     *
     * Whitespace is collapsed rather than preserved: a message that begins with two blank
     * lines would otherwise render as an empty row, which reads as "no message yet".
     */
    fun preview(text: String): String =
        text.replace(Regex("\\s+"), " ").trim().take(ContactCodec.MAX_PREVIEW_LENGTH)

    /** The timestamp a contact is ordered by. */
    private fun activityOf(contact: Contact): Long =
        maxOf(contact.lastMessageAtMillis, contact.addedAtMillis)
}
