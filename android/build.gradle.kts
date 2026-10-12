// Root build file for the SCHAT Android client.
//
// Only two plugins are declared. AGP 9 has built-in Kotlin support and rejects
// `org.jetbrains.kotlin.android`; see the header comment in app/build.gradle.kts
// for the exact errors and the reasoning.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
