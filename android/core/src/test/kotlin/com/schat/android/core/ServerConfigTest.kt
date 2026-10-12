package com.schat.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the connection-URI parser.
 *
 * These run on the JVM, which is the point: the parser is pure logic and gets
 * exercised on every build rather than only when a device happens to be attached.
 */
class ServerConfigTest {

    private val fingerprint = "1199304bc36cba074c90707e9515a73ba570d5d364e30c0dd566a24bb07142f4"

    private fun parse(raw: String) = ServerConfig.parse(raw)

    private fun parseOk(raw: String): ServerConfig {
        val result = parse(raw)
        assertTrue("expected success for $raw but got ${result.exceptionOrNull()}", result.isSuccess)
        return result.getOrThrow()
    }

    private fun parseError(raw: String): String {
        val result = parse(raw)
        assertTrue("expected failure for $raw", result.isFailure)
        return result.exceptionOrNull()!!.message.orEmpty()
    }

    @Test
    fun `parses a complete LAN uri`() {
        val cfg = parseOk("schat://connect?fp=$fingerprint&h=192.168.1.158&n=lan-test&p=8443&ss=1")

        assertEquals("192.168.1.158", cfg.host)
        assertEquals(8443, cfg.port)
        assertEquals("lan-test", cfg.name)
        assertEquals(fingerprint, cfg.fingerprint)
        assertTrue(cfg.selfSigned)
        assertTrue(cfg.isUsable)
        assertNull(cfg.unusableReason())
    }

    @Test
    fun `defaults the port when omitted`() {
        val cfg = parseOk("schat://connect?h=chat.example.com&fp=$fingerprint&ss=1")
        assertEquals(ServerConfig.DEFAULT_PORT, cfg.port)
    }

    @Test
    fun `defaults the name to the host`() {
        val cfg = parseOk("schat://connect?h=chat.example.com&fp=$fingerprint&ss=1")
        assertEquals("chat.example.com", cfg.name)
    }

    @Test
    fun `parses a publicly trusted server without a fingerprint`() {
        val cfg = parseOk("schat://connect?h=chat.example.com&p=443")
        assertFalse(cfg.selfSigned)
        assertEquals("", cfg.fingerprint)
        assertTrue("a CA-issued server needs no pinning", cfg.isUsable)
    }

    @Test
    fun `uppercases in the fingerprint are normalised`() {
        val cfg = parseOk("schat://connect?h=host&ss=1&fp=${fingerprint.uppercase()}")
        assertEquals(fingerprint, cfg.fingerprint)
        assertTrue(cfg.isUsable)
    }

    // ---- the cases that must be refused ------------------------------------

    @Test
    fun `rejects an empty descriptor`() {
        assertTrue(parse("").isFailure)
        assertTrue(parse("   ").isFailure)
    }

    @Test
    fun `rejects a wrong scheme`() {
        val message = parseError("https://connect?h=host")
        assertTrue(message, message.contains("schat://"))
    }

    @Test
    fun `rejects a missing connect authority`() {
        assertTrue(parse("schat://server?h=host").isFailure)
    }

    @Test
    fun `rejects a missing host`() {
        val message = parseError("schat://connect?p=8443")
        assertTrue(message, message.contains("h"))
    }

    @Test
    fun `rejects a host carrying a scheme`() {
        assertTrue(parse("schat://connect?h=https://evil.example").isFailure)
    }

    @Test
    fun `rejects a host carrying a port`() {
        // The port has its own parameter; mixing them is a mistake worth surfacing.
        val message = parseError("schat://connect?h=host:8443")
        assertTrue(message, message.contains("端口"))
    }

    @Test
    fun `rejects a non-numeric port`() {
        assertTrue(parse("schat://connect?h=host&p=abc").isFailure)
    }

    @Test
    fun `rejects an out of range port`() {
        assertTrue(parse("schat://connect?h=host&p=0").isFailure)
        assertTrue(parse("schat://connect?h=host&p=65536").isFailure)
    }

    @Test
    fun `rejects a short fingerprint`() {
        val message = parseError("schat://connect?h=host&ss=1&fp=aabb")
        assertTrue(message, message.contains("指纹"))
    }

    @Test
    fun `rejects a non-hex fingerprint`() {
        assertTrue(parse("schat://connect?h=host&ss=1&fp=${"z".repeat(64)}").isFailure)
    }

    /**
     * The single most dangerous malformed input: a self-signed server with nothing to
     * pin. Accepting it would mean dialling whoever answers first.
     */
    @Test
    fun `rejects a self-signed server with no fingerprint`() {
        val message = parseError("schat://connect?h=192.168.1.158&ss=1")
        assertTrue(message, message.contains("指纹"))
    }

    @Test
    fun `rejects an unknown parameter rather than ignoring it`() {
        // A typo such as http= for h= must not be silently dropped.
        val message = parseError("schat://connect?h=host&ss=1&fp=$fingerprint&http=8443")
        assertTrue(message, message.contains("无法识别"))
    }

    @Test
    fun `rejects a duplicated parameter`() {
        val message = parseError("schat://connect?h=one&h=two&p=8443")
        assertTrue(message, message.contains("重复"))
    }

    // ---- round trip ---------------------------------------------------------

    @Test
    fun `round trips through the uri form`() {
        val original = parseOk("schat://connect?h=192.168.1.158&n=lan-test&p=8443&fp=$fingerprint&ss=1")
        val reparsed = parseOk(original.toUri())

        assertEquals(original, reparsed)
    }

    @Test
    fun `round trips a name containing characters needing escaping`() {
        val original = ServerConfig(
            host = "chat.example.com",
            port = 8443,
            name = "家里的服务器 & 备份",
            fingerprint = fingerprint,
            selfSigned = true,
        )
        assertEquals(original, parseOk(original.toUri()))
    }

    @Test
    fun `isUsable is false exactly when pinning is required but impossible`() {
        val noPin = ServerConfig(
            host = "192.168.1.158",
            port = 8443,
            name = "lan",
            fingerprint = "",
            // Constructed directly: the parser refuses this, which is the point.
            selfSigned = false,
        )
        assertTrue(noPin.isUsable)

        val pinned = noPin.copy(selfSigned = true)
        assertFalse(pinned.isUsable)
        assertNotNull(pinned.unusableReason())
    }

    @Test
    fun `constructor rejects a blank host`() {
        try {
            ServerConfig(host = "  ", port = 8443, name = "x", fingerprint = "", selfSigned = false)
            throw AssertionError("expected an exception")
        } catch (expected: IllegalArgumentException) {
            // as designed
        }
    }
}
