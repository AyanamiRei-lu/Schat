// SCHAT Android client — application module.
//
// AGP 9 NOTES (these are not stylistic choices)
//
// AGP 9.0 and later provide BUILT-IN KOTLIN SUPPORT. Applying
// `org.jetbrains.kotlin.android` now fails the build outright with:
//
//   "The 'org.jetbrains.kotlin.android' plugin is no longer required for Kotlin
//    support since AGP 9.0."
//
// The Compose compiler is likewise wired in by AGP, so neither Kotlin plugin is
// applied here. Kotlin is still very much in use — see the .kt sources under
// src/main/java — it is simply configured by the Android plugin itself.
//
// The Compose compiler is NOT built into AGP and must be applied explicitly:
// without it AGP 9 fails with "Starting in Kotlin 2.0, the Compose Compiler
// Gradle plugin is required when compose is enabled".
//
// AGP 9 also replaced two older DSL surfaces, so `compileSdk { version =
// release(37) }` and `buildTypes { release { optimization { ... } } }` are the
// correct forms, not `compileSdk = 37` and `isMinifyEnabled`.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.schat.android"

    // The development machine has platform 37 and build-tools 37.0.0 installed.
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.schat.android"

        // API 26 (Android 8.0) is the floor. Below it the platform cannot provide
        // a hardware-backed Keystore good enough to bind the vault key, and
        // SCHAT.md section 4.8 makes that binding a security requirement rather
        // than a nicety.
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0-alpha"
    }

    buildFeatures {
        compose = true
    }

    buildTypes {
        release {
            // R8 optimisation and obfuscation stay OFF until the SCS-1 protocol
            // core is linked in as an .aar. Turning R8 on before there is
            // anything to strip can only risk stripping something the crypto
            // layer needs, and a silently broken crypto path is far worse than a
            // larger APK. Revisit in step 8 with a validateable keep-rule set.
            optimization {
                enable = false
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Pure client logic: connection-URI parsing, vault derivation, encrypted store.
    // It has no Android or native dependency, which is what keeps its test suite
    // runnable on the JVM; see core/build.gradle.kts.
    implementation(project(":core"))

    // The SCS-1 protocol core, compiled from Go by tools/build-protocol.ps1.
    //
    // This is a prebuilt .aar rather than a Gradle module on purpose: the protocol
    // is the same Go code the relay and the test suite use, so there is exactly one
    // implementation of the cryptography. Reimplementing it in Kotlin would double
    // the code that must be correct and guarantee eventual divergence.
    //
    // The file is a build artifact and is gitignored; run the script to produce it.
    implementation(files("libs/schat-protocol.aar"))

    // The BOM pins every Compose artifact version; individual Compose
    // dependencies deliberately carry no version so they cannot drift apart.
    implementation(platform(libs.androidx.compose.bom))

    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    // Camera preview and frame analysis for the QR scanner. These live here rather than
    // in :core because they are Android-only, so they have no place in a module whose
    // tests must run on the JVM.
    //
    // ZXing itself arrives transitively through :core; :app never names a ZXing type,
    // because QrCode hands back a plain boolean matrix.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)

    // Tooling is debug-only so it never ships in a release APK.
    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
}
