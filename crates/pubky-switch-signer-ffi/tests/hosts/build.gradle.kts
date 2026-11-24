// The Kotlin host of the signer bindings, built against generated sources and a native
// library: gradle -p tests/hosts -Pbindings=DIR -PnativeLibraryDir=DIR run
plugins {
    kotlin("jvm") version "2.3.21"
    application
}

repositories { mavenCentral() }

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
}

kotlin {
    jvmToolchain(17)
    compilerOptions.allWarningsAsErrors.set(true)
    sourceSets.main {
        kotlin.srcDirs(".", providers.gradleProperty("bindings").get())
        kotlin.include(
            "Main.kt",
            "VaultHost.kt",
            "StoreHost.kt",
            "EnvironmentHost.kt",
            "pubky/switch/signer/pubky_switch_signer_ffi.kt",
        )
    }
}

application {
    mainClass.set("pubky.switch.signer.tests.MainKt")
    applicationDefaultJvmArgs =
        listOf("-Djna.library.path=" + providers.gradleProperty("nativeLibraryDir").get())
}
