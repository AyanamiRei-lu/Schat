package com.schat.android.core.crypto

import mobile.Mobile

/**
 * The production [KeyDeriver], backed by the SCS-1 protocol core in Go.
 *
 * # Why the binding is behind an interface
 *
 * The Go core ships as a native shared library, so it cannot be loaded by a JVM unit
 * test. Putting an interface here means the vault logic — salt handling, two-factor
 * combination, key splitting, passphrase policy — is tested on the JVM against a
 * fake, and only this thin delegate is left to be covered by an instrumented test.
 * The alternative, testing everything on a device, means the interesting logic is
 * tested rarely and slowly, which in practice means it is not tested.
 *
 * # Error handling
 *
 * gomobile reports Go errors by throwing `java.lang.Exception`. Catching and
 * rewrapping keeps a protocol failure from surfacing as a bare, untyped exception at
 * a call site that has no idea what it means.
 */
class GoKeyDeriver : KeyDeriver {

    override fun newSalt(): String = call("生成保险库盐值") { Mobile.newSalt() }

    override fun newRouteKey(): String = call("生成路由密钥") { Mobile.newRouteKey() }

    override fun deriveVaultKey(
        passphrase: String,
        saltHex: String,
        deviceKeyHex: String,
        profile: String,
    ): String = call("派生保险库密钥") {
        Mobile.deriveVaultKey(passphrase, saltHex, deviceKeyHex, profile)
    }

    /**
     * A short description of the protocol core, for the diagnostics screen.
     *
     * Calling into the native library is also the cheapest way for the app to prove
     * at runtime that the AAR actually loaded.
     */
    fun version(): String = call("读取协议版本") { Mobile.version() }

    /** The protocol names in use, for the diagnostics screen. */
    fun protocolName(): String = call("读取协议名称") { Mobile.protocolName() }

    private inline fun <T> call(what: String, block: () -> T): T = try {
        block()
    } catch (e: Exception) {
        throw ProtocolCoreException("协议核心在$what 时失败：${e.message}", e)
    }
}

/** Thrown when the Go protocol core reports a failure. */
class ProtocolCoreException(message: String, cause: Throwable?) : Exception(message, cause)
