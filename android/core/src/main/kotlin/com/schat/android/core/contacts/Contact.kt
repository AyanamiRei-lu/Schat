package com.schat.android.core.contacts

import java.util.Base64

/**
 * One locally remembered peer.
 *
 * # The list lives here and nowhere else
 *
 * A contact is created when a session is established and is stored in the local vault. It
 * is never uploaded, and the relay cannot enumerate it: there is no "add friend" request
 * anywhere in the protocol, because a server that can list who exists on it — and who
 * talks to whom — would be a metadata store that this design exists to avoid.
 *
 * # Why the nickname is local only
 *
 * [nickname] is what *this* user calls the peer. Nothing in the protocol carries it, so it
 * cannot be used to impersonate anyone, and no peer can rename itself in someone else's
 * list. A self-declared display name would need a new encrypted content type, and it would
 * have to be shown as "what they call themselves" rather than as a name, precisely because
 * anyone can claim any name. That is a deliberate omission rather than an oversight, and
 * it can be added later as a pure addition without changing this record's meaning.
 *
 * # What a nickname is not
 *
 * It is not a verification. A contact named "妈妈" is a peer whose identity key this user
 * chose to save under that name; the only thing that establishes who is on the other end
 * is the 60-digit safety number, compared out of band.
 */
data class Contact(
    /** The peer's identity signing public key, lowercase hex. The key of this record. */
    val identityHex: String,

    /** The name this user chose. Empty means "show the abbreviated key". */
    val nickname: String = "",

    /** When the contact was first remembered. */
    val addedAtMillis: Long = 0,

    /** When the most recent message in either direction was seen. 0 when there is none. */
    val lastMessageAtMillis: Long = 0,

    /** A short excerpt of the most recent message, for the list. */
    val lastMessagePreview: String = "",

    /** True when the most recent message was sent by this user. */
    val lastMessageWasOutgoing: Boolean = false,

    /** Messages received since the conversation was last opened. */
    val unread: Int = 0,
) {
    /** What the list shows: the chosen nickname, or an abbreviation of the key. */
    val displayName: String
        get() = nickname.ifBlank { abbreviate(identityHex) }

    /**
     * Whether this contact has been named by the user.
     *
     * The UI shows an unnamed contact's key in full in monospace, because an abbreviated
     * key is easy to confuse with another one and the user may still need to compare it.
     */
    val isNamed: Boolean get() = nickname.isNotBlank()
}

/** Abbreviates a long hex key for display. */
fun abbreviate(identityHex: String): String =
    if (identityHex.length <= 16) identityHex
    else identityHex.take(8) + "…" + identityHex.takeLast(8)

/**
 * Serialisation for the contact list.
 *
 * # Format
 *
 * One contact per line, tab separated, with the two free-text fields Base64 encoded:
 *
 * ```
 * SCHAT-CONTACTS-1
 * <identityHex>\t<nickname b64>\t<addedAt>\t<lastAt>\t<outgoing 0|1>\t<unread>\t<preview b64>
 * ```
 *
 * Base64 rather than escaping, because a nickname containing a tab or a newline would
 * otherwise be able to forge an extra record — and a nickname is user input. The line
 * format rather than JSON for the same reason [com.schat.android.data.store.EncryptedStore]
 * uses one: `org.json` is present on Android but throws on a plain JVM, and this code is
 * meant to be unit tested there.
 *
 * A record that cannot be parsed is DROPPED rather than repaired. Every field matters for
 * identifying the peer, and a half-restored contact would be a contact the user cannot
 * recognise.
 */
object ContactCodec {

    const val MAGIC = "SCHAT-CONTACTS-1"

    /** Bounds the list so a corrupted or hostile vault cannot exhaust memory. */
    const val MAX_CONTACTS = 500

    /** Bounds a nickname. Long enough for a real name, short enough for one line. */
    const val MAX_NICKNAME_LENGTH = 64

    /** Bounds the stored preview. The UI truncates further; this bounds the file. */
    const val MAX_PREVIEW_LENGTH = 200

    fun encode(contacts: List<Contact>): String {
        val builder = StringBuilder(MAGIC).append('\n')
        for (contact in contacts.take(MAX_CONTACTS)) {
            builder
                .append(contact.identityHex).append('\t')
                .append(encodeText(contact.nickname)).append('\t')
                .append(contact.addedAtMillis).append('\t')
                .append(contact.lastMessageAtMillis).append('\t')
                .append(if (contact.lastMessageWasOutgoing) '1' else '0').append('\t')
                .append(contact.unread.coerceAtLeast(0)).append('\t')
                .append(encodeText(contact.lastMessagePreview))
                .append('\n')
        }
        return builder.toString()
    }

    fun decode(text: String): List<Contact> {
        val lines = text.split('\n')
        if (lines.firstOrNull()?.trim() != MAGIC) return emptyList()

        val out = ArrayList<Contact>()
        for (line in lines.drop(1)) {
            if (line.isBlank()) continue
            if (out.size >= MAX_CONTACTS) break

            val parts = line.split('\t')
            if (parts.size != 7) continue

            val identity = parts[0].trim().lowercase()
            if (!isIdentity(identity)) continue

            val nickname = decodeText(parts[1]) ?: continue
            val preview = decodeText(parts[6]) ?: continue

            out.add(
                Contact(
                    identityHex = identity,
                    nickname = sanitiseNickname(nickname),
                    addedAtMillis = parts[2].toLongOrNull() ?: 0L,
                    lastMessageAtMillis = parts[3].toLongOrNull() ?: 0L,
                    lastMessageWasOutgoing = parts[4] == "1",
                    unread = parts[5].toIntOrNull()?.coerceAtLeast(0) ?: 0,
                    lastMessagePreview = preview.take(MAX_PREVIEW_LENGTH),
                ),
            )
        }
        return out
    }

    /**
     * Cleans a nickname for storage and display.
     *
     * Control characters are removed rather than escaped: a newline in a name would break
     * the line-oriented file, and a bidirectional override could make one contact's name
     * render as another's. Both are user input in the literal sense — anyone can type them.
     */
    fun sanitiseNickname(raw: String): String =
        raw.filter { !it.isISOControl() }
            .trim()
            .take(MAX_NICKNAME_LENGTH)

    /** True when [value] is a well-formed identity key. */
    fun isIdentity(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun encodeText(value: String): String =
        Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))

    private fun decodeText(value: String): String? = try {
        String(Base64.getDecoder().decode(value), Charsets.UTF_8)
    } catch (e: IllegalArgumentException) {
        null
    }
}
