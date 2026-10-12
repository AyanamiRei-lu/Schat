package com.schat.android.core.net

import com.schat.android.core.ServerConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

/**
 * Publishes and fetches prekey bundles through the relay.
 *
 * The relay's directory holds only public key material, which is what lets two peers who
 * have never spoken find each other. See `server/internal/directory` for the server half
 * and for the obligation this client has to meet: publishing is unauthenticated, so a
 * fetched bundle must be checked against the identity that was asked for. That check
 * happens in the protocol binding, not here, because it needs the identity comparison to
 * be impossible to skip.
 *
 * Every method blocks. Callers must not invoke them on the UI thread; [ChatController]
 * runs them on a background thread.
 */
class DirectoryClient(
    private val config: ServerConfig,
    private val client: OkHttpClient = RelayClient.defaultClient(config),
) {
    private val base: String = "https://${config.host}:${config.port}/api/v1/keys"

    /**
     * The URL a bundle is published to.
     *
     * The relay requires the identity in the PATH, not only in the body: `ServeHTTP`
     * rejects any request whose path carries no identity with `404 no identity key in the
     * path`, before it looks at the method. Publishing to the bare collection URL is
     * therefore answered with a 404, and because publishing is a fire-and-forget step
     * during startup the only visible symptom is that nobody can ever reach this client.
     *
     * That mistake was made here and caught by the live-relay integration test in
     * `protocol/mobile/relay_integration_test.go`. The URL is built by a named function
     * so the unit test below can assert its exact shape.
     */
    fun publishUrl(identityHex: String): String = "$base/$identityHex"

    /** The URL a bundle is fetched from or withdrawn at. */
    fun bundleUrl(identityHex: String): String = "$base/$identityHex"

    /** Publishes or replaces this client's bundle. */
    fun publish(identityHex: String, bundleJson: String): Result<Unit> = request(
        Request.Builder()
            .url(publishUrl(identityHex))
            .put(bundleJson.toRequestBody(JSON))
            .build(),
    ) { }.map { }

    /** Fetches a peer's bundle as the JSON the protocol binding expects. */
    fun fetch(identityHex: String): Result<String> = request(
        Request.Builder().url(bundleUrl(identityHex)).get().build(),
    ) { body -> body }

    /** Withdraws this client's bundle. */
    fun withdraw(identityHex: String): Result<Unit> = request(
        Request.Builder().url(bundleUrl(identityHex)).delete().build(),
    ) { }.map { }

    private fun <T> request(builder: Request, parse: (String) -> T): Result<T> = try {
        client.newCall(builder).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                Result.failure(
                    IOException("directory returned HTTP ${response.code}${describe(body)}"),
                )
            } else {
                Result.success(parse(body))
            }
        }
    } catch (e: Exception) {
        Result.failure(e)
    }

    /**
     * Pulls the server's `{"error": "..."}` message out of a failed response.
     *
     * Parsed by hand rather than with a JSON library so that this module keeps its
     * dependency list to OkHttp alone.
     */
    private fun describe(body: String): String {
        val marker = "\"error\""
        val start = body.indexOf(marker)
        if (start < 0) return ""
        val colon = body.indexOf(':', start)
        if (colon < 0) return ""
        val open = body.indexOf('"', colon + 1)
        if (open < 0) return ""
        val close = body.indexOf('"', open + 1)
        if (close < 0) return ""
        return ": ${body.substring(open + 1, close)}"
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
    }
}
