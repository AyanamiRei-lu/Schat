package com.schat.android.core.net

import com.schat.android.core.ServerConfig
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * The client half of the relay, against a REAL `schat-server`.
 *
 * # What this closes
 *
 * `PinnedTrust.kt` says of itself that the X.509 wiring "needs a real certificate and
 * therefore a device or an integration test, and that gap is recorded rather than glossed
 * over". This is that test, and it is the last client-to-server seam that could be checked
 * without a phone: the Go tests prove the relay works, the `:core` unit tests prove the
 * configuration logic works, and neither proves that OkHttp actually consults the pinned
 * trust manager, completes a WebSocket upgrade against this server, and gets a reply.
 *
 * # It is skipped unless a relay is named
 *
 * Set `SCHAT_RELAY_URL` (for example `https://192.168.1.158:8443`) and the tests run;
 * leave it unset and they are skipped, so an ordinary `:core:test` stays hermetic. The
 * variable is forwarded explicitly by `core/build.gradle.kts`, because a Gradle test JVM
 * does not reliably inherit the shell's environment when a daemon is already running.
 *
 * Note that a pass here does NOT prove the Android path: this JVM uses the JDK's TLS
 * stack, a phone uses Conscrypt. It does prove the wiring, the command shape and the
 * WebSocket framing, which are the parts that are the same on both.
 */
class RelayLiveTest {

    private val relayUrl: String = System.getenv("SCHAT_RELAY_URL").orEmpty().trim()

    private fun config(host: String, port: Int, fingerprint: String) = ServerConfig(
        host = host,
        port = port,
        name = "live-relay",
        fingerprint = fingerprint,
        selfSigned = true,
    )

    /** Splits `https://host:port` into its parts. */
    private fun endpoint(): Triple<String, Int, String> {
        assumeTrue(
            "set SCHAT_RELAY_URL to a running relay to enable this test",
            relayUrl.isNotEmpty(),
        )
        val withoutScheme = relayUrl.removePrefix("https://").removePrefix("http://")
        val host = withoutScheme.substringBefore(':').substringBefore('/')
        val port = withoutScheme.substringAfter(':', "8443").substringBefore('/').toInt()
        assertTrue("could not parse a host out of $relayUrl", host.isNotEmpty())
        return Triple(host, port, "https://$host:$port")
    }

    /**
     * Reads the relay's advertised fingerprint.
     *
     * Uses a deliberately unpinned client: the point is to obtain the pin the way a user
     * obtains it (out of band from the server's own console), and hardcoding it here would
     * make the test pass only for one certificate.
     */
    private fun advertisedFingerprint(base: String): String {
        var trustManager: X509TrustManager? = null
        val context = SSLContext.getInstance("TLS")
        context.init(
            null,
            arrayOf<TrustManager>(
                object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
                    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                }.also { trustManager = it },
            ),
            SecureRandom(),
        )

        val client = OkHttpClient.Builder()
            .sslSocketFactory(context.socketFactory, trustManager!!)
            .hostnameVerifier { _, _ -> true }
            .build()

        client.newCall(Request.Builder().url("$base/api/v1/health").build()).execute().use { response ->
            val body = response.body?.string().orEmpty()
            assertTrue("the health endpoint answered HTTP ${response.code}: $body", response.isSuccessful)

            val match = Regex("\"fingerprint\"\\s*:\\s*\"([0-9a-fA-F]{64})\"").find(body)
            assertNotNull("the health response carried no fingerprint: $body", match)
            return match!!.groupValues[1].lowercase()
        }
    }

    /** Collects listener callbacks so the test can wait for them deterministically. */
    private class Collector : RelayClient.Listener {
        val events = LinkedBlockingQueue<String>()

        @Volatile
        var connected = false
            private set

        override fun onConnected() {
            connected = true
            events.offer("connected")
        }

        override fun onEnvelope(envelope: ByteArray) {
            events.offer("envelope:${envelope.size}")
        }

        override fun onControl(json: String) {
            events.offer("control:$json")
        }

        override fun onDisconnected(code: Int, reason: String) {
            events.offer("disconnected:$code")
        }

        override fun onFailure(error: Throwable) {
            events.offer("failure:${error.javaClass.simpleName}:${error.message}")
        }

        /** Waits for an event matching [predicate], returning null on timeout. */
        fun await(timeoutMs: Long, predicate: (String) -> Boolean): String? {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (true) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) return null
                val event = events.poll(remaining, TimeUnit.MILLISECONDS) ?: return null
                if (predicate(event)) return event
            }
        }
    }

    @Test
    fun `a pinned connection to the real relay is accepted and the subscription is acknowledged`() {
        val (host, port, base) = endpoint()
        val fingerprint = advertisedFingerprint(base)

        val collector = Collector()
        val client = RelayClient(config(host, port, fingerprint), collector)
        try {
            client.connect()

            assertNotNull(
                "the connection was never established; events: ${collector.events}",
                collector.await(15_000) { it == "connected" },
            )

            assertTrue(
                "the subscribe command was not accepted by the socket",
                client.subscribe(listOf("ab".repeat(16))),
            )

            val reply = collector.await(15_000) { it.startsWith("control:") }
            assertNotNull(
                "the relay never answered the subscription; events: ${collector.events}",
                reply,
            )
            assertTrue("the relay answered $reply, expected an ok", reply!!.contains("\"ok\""))
        } finally {
            client.shutdown()
        }
    }

    @Test
    fun `a hostname that the certificate does not name is still accepted, because the pin is the identity`() {
        // Guards a real trap: pinning and hostname verification are two independent
        // checks, and OkHttp applies both. If the certificate names only `localhost`
        // while the user's URI says `192.168.1.158`, a correctly pinned connection is
        // refused by the hostname check — the user is told the server cannot be trusted
        // when in fact the server was identified perfectly.
        //
        // This test records which way the implementation currently behaves. It connects
        // by IP, which is what a connection URI carries.
        val (host, port, base) = endpoint()
        assumeTrue("this check is about IP-literal hosts", Regex("^\\d+\\.").containsMatchIn(host))

        val fingerprint = advertisedFingerprint(base)
        val collector = Collector()
        val client = RelayClient(config(host, port, fingerprint), collector)
        try {
            client.connect()

            val outcome = collector.await(15_000) { it == "connected" || it.startsWith("failure:") }
            assertNotNull("no outcome within 15s; events: ${collector.events}", outcome)

            assertFalse(
                "connecting by IP with a correct pin failed, which means hostname " +
                    "verification is rejecting a server that was identified correctly: $outcome",
                outcome!!.startsWith("failure:"),
            )
        } finally {
            client.shutdown()
        }
    }

    @Test
    fun `a connection with the wrong pin is refused`() {
        val (host, port, _) = endpoint()

        val collector = Collector()
        val client = RelayClient(config(host, port, "00".repeat(32)), collector)
        try {
            client.connect()

            val outcome = collector.await(15_000) { it == "connected" || it.startsWith("failure:") }
            assertNotNull("no outcome within 15s; events: ${collector.events}", outcome)

            assertFalse(
                "a connection pinned to the WRONG fingerprint was accepted, which means " +
                    "pinning is not actually enforced: $outcome",
                outcome == "connected",
            )
            assertFalse(
                "the client reported a live connection despite the pin mismatch",
                collector.connected,
            )
        } finally {
            client.shutdown()
        }
    }

    @Test
    fun `a self-signed relay with no fingerprint configured is refused`() {
        val (host, port, _) = endpoint()

        val collector = Collector()
        val client = RelayClient(config(host, port, ""), collector)
        try {
            client.connect()

            val outcome = collector.await(15_000) { it == "connected" || it.startsWith("failure:") }
            assertNotNull("no outcome within 15s; events: ${collector.events}", outcome)
            assertFalse(
                "a self-signed relay was accepted with NO pin, which is the one combination " +
                    "that must never be dialled: $outcome",
                outcome == "connected",
            )
            assertEquals(false, collector.connected)
        } finally {
            client.shutdown()
        }
    }
}
