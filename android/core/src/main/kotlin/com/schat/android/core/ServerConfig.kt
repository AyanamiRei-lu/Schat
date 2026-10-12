package com.schat.android.core

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * A parsed `schat://connect?...` server descriptor.
 *
 * This is the entire configuration a SCHAT client needs to reach a relay, and it
 * arrives the same way whether the user scanned a QR code or pasted the string from
 * the server's console output. Keeping one parser for both paths means one place to
 * get validation right.
 *
 * # The fingerprint is not optional in spirit
 *
 * A self-signed deployment is the default, and the only thing that makes it safe is
 * the client pinning the certificate it was told to expect. An attacker on the path
 * can present any certificate; they cannot present one whose SHA-256 matches the
 * value the user obtained out of band. A URI without [fingerprint] therefore still
 * parses (an operator may front the relay with a publicly trusted certificate), but
 * [selfSigned] says whether pinning is required, and the client must refuse to
 * connect to a self-signed server it has no fingerprint for.
 */
data class ServerConfig(
    /** Host name or IP literal. Never contains a scheme or a port. */
    val host: String,

    /** TCP port. */
    val port: Int,

    /** Display name chosen by the operator. */
    val name: String,

    /** Lowercase hex SHA-256 of the server certificate, or empty when absent. */
    val fingerprint: String,

    /** True when the server uses a self-signed certificate that must be pinned. */
    val selfSigned: Boolean,
) {
    init {
        require(host.isNotBlank()) { "host must not be blank" }
        require(port in 1..65535) { "port must be in 1..65535" }
        require(fingerprint.isEmpty() || isFingerprint(fingerprint)) {
            "fingerprint must be 64 lowercase hex characters"
        }
    }

    /**
     * True when this configuration is usable as-is.
     *
     * A self-signed server without a pinned fingerprint is the one combination that
     * must never be dialled: it is precisely the case where an attacker on the path
     * wins for free.
     */
    val isUsable: Boolean
        get() = !selfSigned || fingerprint.isNotEmpty()

    /** The reason [isUsable] is false, for display. */
    fun unusableReason(): String? = when {
        selfSigned && fingerprint.isEmpty() ->
            "服务器使用自签名证书，但配置里没有证书指纹——无法确认连的是正确的服务器。请重新获取连接二维码或 URI。"
        else -> null
    }

    /** Renders the configuration back into its URI form, for storage and QR display. */
    fun toUri(): String {
        val sb = StringBuilder("schat://connect?")
        sb.append("h=").append(encode(host))
        sb.append("&p=").append(port)
        sb.append("&n=").append(encode(name))
        if (fingerprint.isNotEmpty()) {
            sb.append("&fp=").append(fingerprint)
        }
        if (selfSigned) {
            sb.append("&ss=1")
        }
        return sb.toString()
    }

    companion object {
        /** The only scheme this parser accepts. */
        const val SCHEME = "schat"

        /** The authority that marks a connection descriptor. */
        const val AUTHORITY = "connect"

        /** The port assumed when the URI omits one. */
        const val DEFAULT_PORT = 8443

        /** Every query parameter this format defines. */
        private val KNOWN_PARAMETERS = setOf("h", "p", "n", "fp", "ss")

        /**
         * Parses a connection URI.
         *
         * Unknown or repeated parameters are rejected rather than ignored. A typo —
         * `http=` for `h=`, or a duplicated `fp=` — would otherwise be silently
         * dropped and produce a client that connects somewhere unintended, which is
         * exactly the class of failure this format exists to prevent.
         */
        fun parse(raw: String): Result<ServerConfig> {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) {
                return Result.failure(ServerConfigException("连接信息为空"))
            }

            val uri = try {
                URI(trimmed)
            } catch (e: Exception) {
                return Result.failure(ServerConfigException("无法解析连接信息：${e.message}"))
            }

            if (!SCHEME.equals(uri.scheme, ignoreCase = true)) {
                return Result.failure(
                    ServerConfigException("连接信息必须以 schat:// 开头，实际是 ${uri.scheme ?: "（无协议）"}")
                )
            }
            if (!AUTHORITY.equals(uri.host ?: uri.authority, ignoreCase = true)) {
                return Result.failure(ServerConfigException("连接信息缺少 connect：schat://connect?..."))
            }

            val params = linkedMapOf<String, String>()
            val query = uri.rawQuery ?: ""
            if (query.isNotEmpty()) {
                for (pair in query.split('&')) {
                    if (pair.isEmpty()) continue
                    val idx = pair.indexOf('=')
                    val key = if (idx < 0) pair else pair.substring(0, idx)
                    val value = if (idx < 0) "" else pair.substring(idx + 1)

                    val decodedKey = decode(key)
                    if (decodedKey !in KNOWN_PARAMETERS) {
                        return Result.failure(ServerConfigException("无法识别的参数「$decodedKey」"))
                    }
                    if (params.containsKey(decodedKey)) {
                        return Result.failure(ServerConfigException("参数「$decodedKey」重复出现"))
                    }
                    params[decodedKey] = decode(value)
                }
            }

            val host = params["h"].orEmpty().trim()
            if (host.isEmpty()) {
                return Result.failure(ServerConfigException("缺少服务器地址参数 h"))
            }
            if (host.contains("://") || host.contains('/')) {
                return Result.failure(ServerConfigException("服务器地址「$host」不应包含协议或路径"))
            }
            if (host.contains(':')) {
                return Result.failure(
                    ServerConfigException("服务器地址「$host」不应包含端口，端口请用 p 参数指定")
                )
            }

            val port = when (val raw = params["p"]) {
                null, "" -> DEFAULT_PORT
                else -> raw.toIntOrNull()
                    ?: return Result.failure(ServerConfigException("端口「$raw」不是数字"))
            }
            if (port !in 1..65535) {
                return Result.failure(ServerConfigException("端口 $port 超出范围"))
            }

            val fingerprint = params["fp"].orEmpty().trim().lowercase()
            if (fingerprint.isNotEmpty() && !isFingerprint(fingerprint)) {
                return Result.failure(
                    ServerConfigException("证书指纹格式不正确：应为 64 位十六进制字符，实际长度 ${fingerprint.length}")
                )
            }

            val selfSigned = params["ss"] == "1"

            // A self-signed server must come with a fingerprint, and a certificate
            // cannot be both publicly trusted and self-signed. Both contradictions
            // are rejected at parse time so that no later code has to reason about
            // them.
            if (selfSigned && fingerprint.isEmpty()) {
                return Result.failure(
                    ServerConfigException("参数 ss=1 表示自签名证书，但缺少证书指纹 fp")
                )
            }

            val name = params["n"].orEmpty().trim().ifEmpty { host }

            return Result.success(
                ServerConfig(host = host, port = port, name = name, fingerprint = fingerprint, selfSigned = selfSigned)
            )
        }

        /**
         * True when [value] is a lowercase hex SHA-256 fingerprint.
         *
         * Uppercase is rejected rather than normalised because callers lowercase
         * first; accepting both here would let a case-mangled value slip through the
         * one comparison that matters.
         */
        fun isFingerprint(value: String): Boolean =
            value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }
    }
}

/** Thrown for any malformed server descriptor. */
class ServerConfigException(message: String) : Exception(message)

private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

private fun decode(value: String): String = try {
    URLDecoder.decode(value, "UTF-8")
} catch (e: Exception) {
    value
}
