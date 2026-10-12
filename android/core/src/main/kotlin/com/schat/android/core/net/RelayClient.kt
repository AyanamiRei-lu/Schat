package com.schat.android.core.net

import com.schat.android.core.ServerConfig
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit

/**
 * The client half of the relay protocol.
 *
 * It speaks exactly what `server/internal/gateway` documents:
 *
 *   client -> server  TEXT    {"t":"sub"|"unsub","tokens":["<32 hex>", ...]}
 *   client -> server  TEXT    {"t":"hb"}
 *   client -> server  BINARY  token(16 bytes) || SCS-1 frame
 *   server -> client  BINARY  the same envelope, byte for byte
 *   server -> client  TEXT    {"t":"ok"|"hb"|"delivered"|"queued"|"offline"|"err", ...}
 *
 * # Independence from the envelope format
 *
 * This class never looks inside an envelope. It moves opaque bytes and hands them to
 * the protocol core, which is the only thing that can decrypt them. That mirrors the
 * relay's own design, and it means a change to SCS-1 framing cannot break networking.
 *
 * # Why the client cannot silently fall back to plaintext
 *
 * There is deliberately no constructor flag that disables TLS by default. A relay
 * configured with `--no-tls` exists only for local debugging, and the connection URI
 * has no field that expresses it, so a client reading such a URI has no way to know it
 * should downgrade — which is the correct failure direction.
 */
class RelayClient(
    private val config: ServerConfig,
    private val listener: Listener,
    private val client: OkHttpClient = defaultClient(config),
) {
    /** Callbacks. They arrive on OkHttp's reader thread, not the UI thread. */
    interface Listener {
        fun onConnected()
        fun onEnvelope(envelope: ByteArray)

        /** A JSON control reply, passed through unparsed. */
        fun onControl(json: String)

        fun onDisconnected(code: Int, reason: String)
        fun onFailure(error: Throwable)
    }

    private var socket: WebSocket? = null

    /** The endpoint this client dials. */
    val url: String
        get() = "wss://${config.host}:${config.port}/ws"

    /** Opens the connection. Completion is reported through [Listener.onConnected]. */
    fun connect() {
        socket = client.newWebSocket(Request.Builder().url(url).build(), SocketListener())
    }

    /** Subscribes to mailboxes, addressed by their hex delivery tokens. */
    fun subscribe(tokens: List<String>): Boolean =
        sendText(command("sub", tokens))

    /** Stops listening on mailboxes. */
    fun unsubscribe(tokens: List<String>): Boolean =
        sendText(command("unsub", tokens))

    /** Application-level keepalive, in addition to the transport's own pings. */
    fun heartbeat(): Boolean = sendText("""{"t":"hb"}""")

    /**
     * Deposits one envelope: a 16-byte delivery token followed by an SCS-1 frame.
     *
     * The caller builds the bytes; this class does not know or care what is in them.
     */
    fun sendEnvelope(envelope: ByteArray): Boolean {
        if (envelope.size <= TOKEN_SIZE) {
            // A payload with no room for a frame is a caller bug, and sending it would
            // only earn an error reply.
            return false
        }
        return socket?.send(envelope.toByteString()) ?: false
    }

    /** Closes the connection, completing the WebSocket closing handshake. */
    fun close() {
        socket?.close(CLOSE_NORMAL, "client closing")
        socket = null
    }

    /** Releases the underlying threads. Call when the client is discarded. */
    fun shutdown() {
        close()
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
    }

    private fun sendText(text: String): Boolean = socket?.send(text) ?: false

    private fun command(type: String, tokens: List<String>): String {
        // Built by hand rather than with a JSON library. Delivery tokens are hex, so
        // the values cannot contain characters needing escape, and keeping JSON parsing
        // out of this layer is what lets the whole module stay free of an Android-only
        // dependency.
        val list = tokens.joinToString(",") { "\"$it\"" }
        return """{"t":"$type","tokens":[$list]}"""
    }

    private inner class SocketListener : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            listener.onConnected()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            listener.onControl(text)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            listener.onEnvelope(bytes.toByteArray())
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            // Finish the closing handshake rather than leaving it half done.
            webSocket.close(code, null)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            listener.onDisconnected(code, reason)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            listener.onFailure(t)
        }
    }

    companion object {
        /** The delivery token length, mirrored from the protocol. */
        const val TOKEN_SIZE = 16

        private const val CLOSE_NORMAL = 1000

        /**
         * Builds the HTTP client.
         *
         * Two settings matter:
         *
         *   - the read timeout is disabled, because a WebSocket is idle by nature and a
         *     read timeout would tear down a healthy quiet connection;
         *   - when a fingerprint is configured, the pinned trust manager replaces the
         *     platform one, so a self-signed relay is accepted only if it presents the
         *     exact certificate the user was told to expect.
         */
        fun defaultClient(config: ServerConfig): OkHttpClient {
            val builder = OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)

            if (config.fingerprint.isNotEmpty()) {
                val context = pinnedSslContext(config)
                builder.sslSocketFactory(context.socketFactory, PinnedTrustManager(config))
            }

            return builder.build()
        }
    }
}
