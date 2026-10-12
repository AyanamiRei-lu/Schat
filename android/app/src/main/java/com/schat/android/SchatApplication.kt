package com.schat.android

import android.app.Application

/**
 * Application entry point.
 *
 * The override below is deliberately empty, and that emptiness is the point.
 *
 * SCHAT initialises no analytics SDK, no crash reporter, no advertising
 * identifier, no attribution library and no remote-configuration client. A
 * reader auditing SCHAT.md section 12.5 ("does not collect your data") should be
 * able to open this file, see that [onCreate] does nothing but call super, and
 * be done. Every dependency that would need initialising here is a dependency
 * the project must not have.
 */
class SchatApplication : Application() {

    override fun onCreate() {
        super.onCreate()
    }
}
