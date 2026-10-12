import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// :core holds every piece of SCHAT client logic that does not touch Android.
//
// WHY THIS MODULE EXISTS
//
// The first version of this code lived in :app, alongside the gomobile .aar. That
// made its unit tests unrunnable: Gradle's test executor loads the whole runtime
// classpath, the gomobile-generated `go.Seq` class mangles that classpath during its
// static initialiser, and the JVM dies with a ClassNotFoundException built out of a
// fragment of the machine's PATH. The tests never started.
//
// The lesson is not "work around the AAR". It is that logic which has no Android
// dependency should not be compiled into a module that does: a 40-case test suite
// that only runs when a device is attached is, in practice, a test suite that does
// not run. Splitting the module makes `:core:test` fast, hermetic and part of every
// build, while the thin Android bindings stay in :app where an instrumented test
// covers them.
//
// Depends on: nothing but the Kotlin standard library.
//
// The plugin is applied WITHOUT a version on purpose. AGP 9 already puts the Kotlin
// Gradle plugin on the build classpath (it provides AGP's built-in Kotlin support),
// and asking for a specific version then fails with "the plugin is already on the
// classpath with an unknown version". Naming no version uses the one that is already
// there, which is also the one :app is compiled with — so the two modules cannot
// drift onto different Kotlin compilers.
plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        // Must match :app, or the two modules cannot be linked.
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // The WebSocket client. Pure JVM, so it belongs here rather than in :app — which
    // also means the parts of it that can be tested are tested on every build.
    implementation(libs.okhttp)

    // QR encoding and decoding. Pure Java, so it belongs here for the same reason: the
    // payload format and the encode/decode round trip are then covered by this module's
    // suite instead of depending on a camera and a hand to hold it.
    //
    // `implementation` rather than `api` on purpose: nothing ZXing-shaped crosses this
    // module's public surface. QrCode.encode hands back a plain Array<BooleanArray>.
    implementation(libs.zxing.core)

    testImplementation(libs.junit)
}

// RelayLiveTest talks to a real `schat-server` when a relay is named, and is skipped
// otherwise. The value is passed as a Gradle property rather than read from the shell:
//
//   .\gradlew.bat :core:test "-Pschat.relayUrl=https://192.168.1.158:8443"
//
// QUOTE THE ARGUMENT. PowerShell 5.1 splits `-Pschat.relayUrl=...` on the dot and hands
// Gradle a bare `.relayUrl=https://...`, which Gradle then reports as "Cannot locate tasks
// that match '.relayUrl=https://...'". The failure looks like a Gradle problem and is not.
//
// WHY NOT `System.getenv("SCHAT_RELAY_URL")`
//
// Because a Gradle daemon outlives the shell that started it. A daemon launched once with
// the variable set keeps it for every later build, so a plain `:core:test` would quietly
// start dialling a relay that may well be down — turning an integration test into a
// source of mysterious failures. The variable is therefore set explicitly on every run,
// to the property when given and to the EMPTY STRING when not, which overrides anything
// inherited from the daemon.
tasks.withType<Test>().configureEach {
    environment("SCHAT_RELAY_URL", (project.findProperty("schat.relayUrl") as String?).orEmpty())

    testLogging {
        // Without this an integration test that skipped itself looks exactly like one
        // that passed.
        events("skipped", "failed", "passed")
        showStandardStreams = false
    }
}
