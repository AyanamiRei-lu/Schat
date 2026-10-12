// ---------------------------------------------------------------------------
// WHY A CHINESE MIRROR IS LISTED FIRST
//
// On this development network, Maven Central is intermittently served through something
// that presents a certificate not matching the host name:
//
//   Certificate for <repo.maven.apache.org> doesn't match any of the subject
//   alternative names: [117.55.193.154, 2406:cb42:0:2018:0:0:0:2]
//
// That is DNS interception or a transparent proxy. It makes every dependency the local
// cache does not already hold fail, and it fails slowly: the build retried for eleven
// minutes before giving up. The mirrors below are therefore tried FIRST, so the build does
// not depend on a route that is being tampered with.
//
// THIS IS A TRUST DECISION, AND IT IS NOT FREE.
//
// A mirror is a third party that can serve whatever bytes it likes under the coordinates
// you asked for. Aliyun's mirror is a faithful copy of Maven Central, is operated by
// Alibaba Cloud and is very widely used — but for a project whose entire subject is
// trustworthy software, that trust belongs in writing rather than in an implicit default.
// The canonical repositories are therefore still listed, AFTER the mirrors, and this
// comment says how to remove the mirrors entirely.
//
// To build from the canonical sources only, delete the three
// `maven("https://maven.aliyun.com/...")` lines in each of the two blocks below. Nothing
// else in this file depends on them.
//
// The URLs are written out twice rather than shared through a property because Gradle
// requires `pluginManagement` to be the first block in this file, which rules out
// declaring the list before it.
// ---------------------------------------------------------------------------

pluginManagement {
    repositories {
        // Mirrors first: the direct routes are the ones being intercepted.
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")

        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

// Resolves and provisions the JDK toolchain declared in
// gradle/gradle-daemon-jvm.properties (JDK 25). Without this plugin Gradle
// refuses to run when the requested toolchain is not already installed.
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")

        google()
        mavenCentral()
    }
}

rootProject.name = "schat"

// The Android client. The protocol core that this app will consume is built
// from ../../protocol by tools/build-protocol.ps1 via gomobile and dropped into
// app/libs as an .aar; see SCHAT.md section 3.
include(":app")

// Pure Kotlin/JVM logic: connection-URI parsing, the vault, the encrypted store and
// the crypto interfaces. It deliberately does NOT depend on the gomobile .aar, so
// its unit tests run on the JVM in every build. See core/build.gradle.kts for why
// that separation is not merely tidiness.
include(":core")

// The relay server lives in ../../server and is built separately with the Go
// toolchain. It is intentionally not a Gradle subproject: the client and the
// server share no code, only the SCS-1 specification (SCHAT.md section 9.1).
