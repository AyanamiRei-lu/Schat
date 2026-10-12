package com.schat.android.core.qr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The QR payload format.
 *
 * This is where a mistyped character used to cost a whole debugging round: a wrong hex
 * digit produces the same "no bundle published for that identity" error as a peer that
 * genuinely never published, so the two are indistinguishable from the symptom. A scanned
 * payload removes the typo, which is only true if the parsing is exactly right.
 */
class QrPayloadTest {

    private val identity = "a951b5f835dd154622a5bf766a33c2ca475cef6d0688e7a54949a2f5592feef1"

    private val serverUri = "schat://connect?fp=eaa60c0122806c861bf30f599a624e46114ded9b" +
        "568916c146b4fd414ebed325&h=192.168.1.158&n=my-relay&p=8443&ss=1"

    @Test
    fun `an identity renders as a typed URI`() {
        assertEquals("schat://id?i=$identity", QrPayload.identity(identity))
    }

    @Test
    fun `rendering normalises case and trims`() {
        assertEquals("schat://id?i=$identity", QrPayload.identity(identity.uppercase()))
        assertEquals("schat://id?i=$identity", QrPayload.identity("  $identity\n"))
    }

    @Test
    fun `a rendered identity parses back to itself`() {
        val parsed = QrPayload.parse(QrPayload.identity(identity))
        assertEquals(QrPayload.Identity(identity), parsed)
    }

    @Test
    fun `a bare hex identity is accepted`() {
        // Accepted so that a code produced by any other tool still works.
        assertEquals(QrPayload.Identity(identity), QrPayload.parse(identity))
        assertEquals(QrPayload.Identity(identity), QrPayload.parse(identity.uppercase()))
    }

    @Test
    fun `surrounding whitespace never breaks a payload`() {
        assertEquals(QrPayload.Identity(identity), QrPayload.parse(" $identity "))
        assertEquals(QrPayload.Identity(identity), QrPayload.parse("\n$identity\n"))
        assertEquals(
            QrPayload.ServerConfig(serverUri),
            QrPayload.parse("\n$serverUri\t"),
        )
    }

    @Test
    fun `a connection URI parses as a connection and keeps its exact text`() {
        val parsed = QrPayload.parse(serverUri)
        assertEquals(QrPayload.ServerConfig(serverUri), parsed)

        // Passed through unchanged: the server already prints this format, and the client
        // must not become a second definition of it.
        assertTrue(parsed is QrPayload.ServerConfig)
    }

    @Test
    fun `the two payload kinds are never confused`() {
        // A connection URI must not be read as an identity, or the app would try to dial
        // an identity as a server.
        assertTrue(QrPayload.parse(serverUri) is QrPayload.ServerConfig)

        // Even a bare, incomplete one stays a connection payload rather than becoming
        // null: rejecting it is ServerConfig's job, and ServerConfig says "缺少证书指纹"
        // where this layer could only say "this is not a SCHAT code".
        assertTrue(QrPayload.parse(serverUri.substringBefore('?')) is QrPayload.ServerConfig)

        // ...and an identity must not be read as a connection.
        assertTrue(QrPayload.parse(QrPayload.identity(identity)) is QrPayload.Identity)
    }

    @Test
    fun `malformed identities are rejected`() {
        val bad = listOf(
            "schat://id",                              // no query at all
            "schat://id?",                             // empty query
            "schat://id?i=",                            // empty value
            "schat://id?i=" + identity.dropLast(1),     // 63 characters
            "schat://id?i=" + identity + "ab",          // 66 characters
            "schat://id?i=" + "z".repeat(64),           // right length, not hex
            "schat://id?x=$identity",                   // wrong parameter name
            "schat://ident?i=$identity",                // wrong host
            identity.dropLast(1),                        // bare, too short
            "z".repeat(64),                              // bare, not hex
        )

        for (candidate in bad) {
            assertNull("should have been rejected: $candidate", QrPayload.parse(candidate))
        }
    }

    @Test
    fun `foreign content is rejected rather than guessed at`() {
        val foreign = listOf(
            null,
            "",
            "   ",
            "hello",
            "https://example.com/?i=$identity",
            "WIFI:S=MyNetwork;T=WPA;P=secret;;",
            "just some text with $identity inside it",
        )

        for (candidate in foreign) {
            assertNull("should have been rejected: $candidate", QrPayload.parse(candidate))
        }
    }

    @Test
    fun `a connection payload is left for ServerConfig to validate`() {
        // This layer must not duplicate that validation: two definitions of what a valid
        // connection URI is would eventually disagree, and the one that ran first would
        // win silently.
        val incomplete = "schat://connect?h=192.168.1.158&ss=1"
        assertEquals(QrPayload.ServerConfig(incomplete), QrPayload.parse(incomplete))
    }
}
