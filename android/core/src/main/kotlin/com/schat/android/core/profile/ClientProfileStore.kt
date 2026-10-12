package com.schat.android.core.profile

import com.schat.android.data.store.EncryptedStore

/**
 * Everything a working client needs, as an opaque bundle of strings.
 *
 * The identity and prekey material are produced by the Go protocol core and handed
 * over as JSON. They are treated as opaque here on purpose: this layer's job is to
 * store them, not to understand them, and keeping it ignorant means a change to the
 * protocol's serialisation cannot break persistence.
 */
data class ClientProfileData(
    /** The identity key pair, as produced by the protocol core. */
    val identityJson: String,

    /** The prekey pool, as produced by the protocol core. */
    val prekeyStoreJson: String,

    /** The delivery route key, hex. */
    val routeKeyHex: String,

    /** The recovery code, formatted for display. */
    val recoveryCode: String,

    /** The relay this client is pointed at, as a `schat://` URI. */
    val serverUri: String,
)

/**
 * Persists the client profile inside the encrypted store.
 *
 * # Why the recovery code is stored
 *
 * The user was told to write it down, and they should have. Storing it anyway costs a
 * few hundred bytes and means a user who lost the paper can still see the code behind
 * the vault — which is behind the passphrase and the device key. Refusing to store it
 * would be security theatre: anyone who can read this store already has everything the
 * recovery code protects.
 *
 * # Why the prekeys are stored
 *
 * A one-time prekey must be consumed exactly once, and that has to survive a restart.
 * If the pool lived only in memory, a fresh pool would be generated on every launch
 * and a peer could consume the same prekey again — the precise failure the one-time
 * pool exists to prevent.
 */
class ClientProfileStore(private val store: EncryptedStore) {

    /** True when every required record is present. */
    fun isComplete(): Boolean = REQUIRED.all { store.contains(it) }

    /** Writes the whole profile, replacing anything previously stored. */
    fun save(data: ClientProfileData) {
        store.putString(KEY_IDENTITY, data.identityJson)
        store.putString(KEY_PREKEYS, data.prekeyStoreJson)
        store.putString(KEY_ROUTE_KEY, data.routeKeyHex)
        store.putString(KEY_RECOVERY, data.recoveryCode)
        store.putString(KEY_SERVER, data.serverUri)
    }

    /**
     * Reads the profile back.
     *
     * A partially present profile returns null rather than a half-filled object. An
     * identity without its prekeys cannot complete a handshake, and surfacing that as
     * a working profile would push the failure into the protocol layer where it would
     * be much harder to explain.
     */
    fun load(): ClientProfileData? {
        if (!isComplete()) return null

        return ClientProfileData(
            identityJson = store.getString(KEY_IDENTITY) ?: return null,
            prekeyStoreJson = store.getString(KEY_PREKEYS) ?: return null,
            routeKeyHex = store.getString(KEY_ROUTE_KEY) ?: return null,
            recoveryCode = store.getString(KEY_RECOVERY) ?: return null,
            serverUri = store.getString(KEY_SERVER) ?: return null,
        )
    }

    /** Removes every record belonging to the profile. */
    fun clear() {
        REQUIRED.forEach { store.remove(it) }
    }

    private companion object {
        const val KEY_IDENTITY = "profile.identity"
        const val KEY_PREKEYS = "profile.prekeys"
        const val KEY_ROUTE_KEY = "profile.routeKey"
        const val KEY_RECOVERY = "profile.recovery"
        const val KEY_SERVER = "profile.server"

        val REQUIRED = listOf(KEY_IDENTITY, KEY_PREKEYS, KEY_ROUTE_KEY, KEY_RECOVERY, KEY_SERVER)
    }
}
