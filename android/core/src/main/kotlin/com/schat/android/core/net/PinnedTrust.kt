package com.schat.android.core.net

import com.schat.android.core.ServerConfig
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Certificate pinning for a self-signed relay.
 *
 * # Why pinning rather than a trust store
 *
 * SCHAT's default deployment uses a self-signed certificate, which no public CA will
 * vouch for. The alternative to pinning would be to accept any certificate, and that
 * would hand an attacker on the path the ability to sit in the middle of every
 * connection — reading the metadata the transport exists to protect, and rewriting the
 * delivery tokens that decide where envelopes go.
 *
 * Pinning the fingerprint the user obtained out of band closes that. It is the same
 * trust model as comparing a safety number: the secret is exchanged through a channel
 * the attacker does not control.
 *
 * # What is verified here, and what is not
 *
 * The fingerprint comparison and the refusal to trust anything without a pinned value
 * are covered by unit tests. The X.509 wiring — that OkHttp actually consults this
 * manager, that a real self-signed certificate is accepted, that a real other one is
 * rejected, and that a WebSocket upgrade against a real relay completes — is covered by
 * [RelayLiveTest], which runs against a live `schat-server` when one is named:
 *
 * ```
 * .\gradlew.bat :core:test "-Pschat.relayUrl=https://192.168.1.158:8443"
 * ```
 *
 * (The quotes are required: PowerShell 5.1 splits the argument on the dot otherwise.)
 *
 * What remains device-only is the Android TLS stack itself: these tests use the JDK's
 * provider, a phone uses Conscrypt, and the Keystore-backed vault has no JVM equivalent
 * at all. That part is recorded in SECURITY.md rather than glossed over.
 */

/** The lowercase hex SHA-256 of a certificate's DER encoding. */
fun fingerprintOf(encoded: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(encoded).joinToString("") { "%02x".format(it) }

/**
 * True when a certificate's DER encoding matches an expected fingerprint.
 *
 * The comparison is constant time. A fingerprint is not a long-term secret, but a
 * comparison that returns early on the first differing byte would let an attacker on
 * the path discover a valid fingerprint byte by byte — and they only need to match it
 * once to be trusted forever.
 */
fun fingerprintMatches(encoded: ByteArray, expectedHex: String): Boolean {
    val expected = expectedHex.trim().lowercase()
    if (expected.length != 64) return false
    return MessageDigest.isEqual(
        fingerprintOf(encoded).toByteArray(Charsets.US_ASCII),
        expected.toByteArray(Charsets.US_ASCII),
    )
}

/**
 * A trust manager that accepts exactly one certificate: the pinned one.
 *
 * It implements [X509TrustManager] rather than extending the platform default, because
 * the platform default would accept any publicly trusted certificate — which is
 * precisely the outcome pinning exists to prevent.
 */
class PinnedTrustManager(private val config: ServerConfig) : X509TrustManager {

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // This manager is only ever used to validate the server. Refusing outright is
        // safer than silently accepting, which is what an empty implementation would do.
        throw CertificateException("this trust manager validates servers only")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (chain.isNullOrEmpty()) {
            throw CertificateException("the server presented no certificate")
        }
        if (config.fingerprint.isEmpty()) {
            throw CertificateException(
                "no certificate fingerprint is configured, so the server cannot be identified"
            )
        }

        val leaf = chain[0]
        if (!fingerprintMatches(leaf.encoded, config.fingerprint)) {
            throw CertificateException(
                "the server certificate does not match the pinned fingerprint"
            )
        }
    }

    /**
     * Reports no accepted issuers.
     *
     * The value is only used to build the certificate-request list during a TLS
     * client-authentication handshake, which SCHAT does not use; returning the pin
     * itself would imply it is an issuer, which it is not.
     */
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/**
 * Builds the TLS context for a relay connection.
 *
 * TLS 1.2 is the floor, matching the server's own choice: Android 8 and 9 cannot speak
 * TLS 1.3, and those are the devices `minSdk` 26 targets.
 */
fun pinnedSslContext(config: ServerConfig): SSLContext {
    val context = SSLContext.getInstance("TLS")
    context.init(null, arrayOf<TrustManager>(PinnedTrustManager(config)), SecureRandom())
    return context
}
