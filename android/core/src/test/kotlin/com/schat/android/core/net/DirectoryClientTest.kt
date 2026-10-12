package com.schat.android.core.net

import com.schat.android.core.ServerConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * URL construction for the prekey directory.
 *
 * # Why a dedicated test for three string concatenations
 *
 * Because getting one of them wrong is invisible. Publishing happens during startup,
 * its failure is logged into a status line the user may not be looking at, and the only
 * real symptom is that no peer can ever reach this client — which looks exactly like
 * "the other side never came online".
 *
 * That is not hypothetical: `publish` used to PUT to the bare collection path, and the
 * relay answers that with `404 no identity key in the path` because `ServeHTTP` requires
 * the identity in the path regardless of method. A live-relay integration test caught it;
 * this test pins the fix so it cannot come back without a red test.
 */
class DirectoryClientTest {

    private val identity = "cd".repeat(32)

    private fun client(port: Int = 8443) = DirectoryClient(
        ServerConfig(
            host = "192.0.2.10",
            port = port,
            name = "test",
            fingerprint = "ab".repeat(32),
            selfSigned = true,
        ),
    )

    @Test
    fun `publish addresses the identity path`() {
        assertEquals(
            "https://192.0.2.10:8443/api/v1/keys/$identity",
            client().publishUrl(identity),
        )
    }

    @Test
    fun `publish never addresses the bare collection path`() {
        val url = client().publishUrl(identity)

        // The regression: a trailing slash with nothing after it.
        assertFalse(
            "publishing to the collection path is answered with 404: $url",
            url.endsWith("/keys/"),
        )
        assertFalse("publishing to the collection path is answered with 404: $url", url.endsWith("/keys"))
    }

    @Test
    fun `fetch and withdraw address the identity path`() {
        val expected = "https://192.0.2.10:8443/api/v1/keys/$identity"
        assertEquals(expected, client().bundleUrl(identity))
    }

    @Test
    fun `the port is carried through`() {
        assertTrue(client(port = 9443).publishUrl(identity).startsWith("https://192.0.2.10:9443/"))
    }

    @Test
    fun `the identity is placed once and unencoded`() {
        // The relay matches the identity against its own hex parsing, so the client must
        // not percent-encode it or add anything around it.
        val url = client().publishUrl(identity)
        assertEquals(1, Regex(Regex.escape(identity)).findAll(url).count())
        assertFalse(url.contains("%"))
    }
}
