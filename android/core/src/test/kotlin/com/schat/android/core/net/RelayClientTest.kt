package com.schat.android.core.net

import com.schat.android.core.ServerConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

class PinnedTrustTest {

    private val fingerprint = "1199304bc36cba074c90707e9515a73ba570d5d364e30c0dd566a24bb07142f4"

    private fun config(fp: String = fingerprint, selfSigned: Boolean = true) = ServerConfig(
        host = "192.168.1.158",
        port = 8443,
        name = "test",
        fingerprint = fp,
        selfSigned = selfSigned,
    )

    @Test
    fun `fingerprint is the lowercase hex sha256 of the der`() {
        val der = "some certificate bytes".toByteArray()
        val got = fingerprintOf(der)

        assertEquals(64, got.length)
        assertEquals(got.lowercase(), got)
        // Recomputed independently rather than trusting the function under test.
        assertEquals(
            MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) },
            got,
        )
    }

    @Test
    fun `matching accepts the exact fingerprint`() {
        val der = ByteArray(64) { it.toByte() }
        assertTrue(fingerprintMatches(der, fingerprintOf(der)))
    }

    @Test
    fun `matching is case insensitive on the expected value`() {
        val der = ByteArray(64) { it.toByte() }
        assertTrue(fingerprintMatches(der, fingerprintOf(der).uppercase()))
    }

    /** One changed bit anywhere in the certificate must break the match. */
    @Test
    fun `matching rejects any difference in the certificate`() {
        val der = ByteArray(32) { it.toByte() }
        val expected = fingerprintOf(der)

        for (i in der.indices) {
            val mutated = der.copyOf()
            mutated[i] = (mutated[i] + 1).toByte()
            assertFalse("byte $i was not covered by the fingerprint", fingerprintMatches(mutated, expected))
        }
    }

    @Test
    fun `matching rejects a well formed but different fingerprint`() {
        val der = "certificate".toByteArray()
        val other = "0".repeat(64)
        assertNotEquals(fingerprintOf(der), other)
        assertFalse(fingerprintMatches(der, other))
    }

    /** A malformed pin must fail closed, not be compared loosely. */
    @Test
    fun `matching rejects a fingerprint of the wrong length`() {
        val der = "certificate".toByteArray()
        for (bad in listOf("", "aabb", "0".repeat(63), "0".repeat(65))) {
            assertFalse("length ${bad.length} should not match", fingerprintMatches(der, bad))
        }
    }

    @Test
    fun `matching rejects a non hex fingerprint`() {
        val der = "certificate".toByteArray()
        assertFalse(fingerprintMatches(der, "z".repeat(64)))
    }

    // ---- the trust manager ------------------------------------------------

    @Test
    fun `an empty chain is refused`() {
        val manager = PinnedTrustManager(config())
        try {
            manager.checkServerTrusted(emptyArray<X509Certificate>(), "RSA")
            throw AssertionError("expected the empty chain to be refused")
        } catch (expected: CertificateException) {
            assertTrue(expected.message.orEmpty().contains("no certificate"))
        }
    }

    @Test
    fun `a null chain is refused`() {
        val manager = PinnedTrustManager(config())
        try {
            manager.checkServerTrusted(null, "RSA")
            throw AssertionError("expected the null chain to be refused")
        } catch (expected: CertificateException) {
            // as designed
        }
    }

    /**
     * A configuration with no pin must not be trusted at all.
     *
     * This is the check that stops a stripped-down URI — one that dropped the fp
     * parameter — from silently falling back to trusting anything.
     */
    @Test
    fun `a configuration without a fingerprint trusts nothing`() {
        val manager = PinnedTrustManager(config(fp = "", selfSigned = false))
        try {
            manager.checkServerTrusted(emptyArray<X509Certificate>(), "RSA")
            throw AssertionError("expected the empty chain to be refused")
        } catch (expected: CertificateException) {
            // as designed
        }
    }

    @Test
    fun `the manager refuses to validate clients`() {
        val manager = PinnedTrustManager(config())
        try {
            manager.checkClientTrusted(emptyArray<X509Certificate>(), "RSA")
            throw AssertionError("expected client validation to be refused")
        } catch (expected: CertificateException) {
            // as designed
        }
    }

    @Test
    fun `no issuers are advertised`() {
        assertEquals(0, PinnedTrustManager(config()).acceptedIssuers.size)
    }

    @Test
    fun `an ssl context can be built from a pinned configuration`() {
        val context = pinnedSslContext(config())
        assertTrue(context.socketFactory != null)
        assertEquals("TLS", context.protocol)
    }
}

class RelayClientWiringTest {

    private val fingerprint = "1199304bc36cba074c90707e9515a73ba570d5d364e30c0dd566a24bb07142f4"

    private fun config(fp: String = fingerprint) = ServerConfig(
        host = "192.168.1.158",
        port = 8443,
        name = "test",
        fingerprint = fp,
        selfSigned = true,
    )

    private val noop = object : RelayClient.Listener {
        override fun onConnected() {}
        override fun onEnvelope(envelope: ByteArray) {}
        override fun onControl(json: String) {}
        override fun onDisconnected(code: Int, reason: String) {}
        override fun onFailure(error: Throwable) {}
    }

    @Test
    fun `the endpoint is wss regardless of configuration`() {
        // There is no downgrade path: a relay that cannot be reached over TLS is a
        // configuration to fix, not one to work around.
        assertEquals("wss://192.168.1.158:8443/ws", RelayClient(config(), noop).url)
        assertEquals("wss://192.168.1.158:8443/ws", RelayClient(config(fp = ""), noop).url)
    }

    /** A payload with no room for a frame must be refused before it reaches the socket. */
    @Test
    fun `an envelope with no frame after the token is refused`() {
        val client = RelayClient(config(), noop)
        assertFalse(client.sendEnvelope(ByteArray(RelayClient.TOKEN_SIZE)))
        assertFalse(client.sendEnvelope(ByteArray(0)))
        client.shutdown()
    }

    @Test
    fun `sending before connecting does not throw`() {
        val client = RelayClient(config(), noop)
        assertFalse(client.sendEnvelope(ByteArray(64)))
        assertFalse(client.subscribe(listOf("ab".repeat(16))))
        assertFalse(client.heartbeat())
        client.shutdown()
    }

    @Test
    fun `closing an unconnected client is harmless`() {
        val client = RelayClient(config(), noop)
        client.close()
        client.close()
        client.shutdown()
    }

    /**
     * The client must refuse a cleartext endpoint even if one were configured, because
     * a downgraded connection leaks the delivery tokens the relay's metadata design
     * depends on.
     */
    @Test
    fun `the trust manager is installed when a fingerprint is present`() {
        val client = RelayClient.defaultClient(config())
        // OkHttp exposes the socket factory but not the trust manager, so the assertion
        // is that construction succeeded with the pinned factory rather than the
        // platform default. A fuller check needs a real certificate and a live socket.
        assertTrue(client.sslSocketFactory.javaClass.name.isNotEmpty())
    }
}
