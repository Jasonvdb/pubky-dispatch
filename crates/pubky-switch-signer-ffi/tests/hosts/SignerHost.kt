// The Kotlin host's checks of the signer's life cycle.
package pubky.switch.signer.tests

import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import pubky.switch.signer.*

private const val signerOrigin = "https://switch.example"
private const val signerChildMarker = "--signer-child"

private fun signerVault() = MemoryVault().also { it.import() }

private suspend fun signerFailureFrom(what: String, call: suspend () -> Unit): SignerFfiException {
    try {
        call()
    } catch (failure: SignerFfiException) {
        return failure
    }
    throw IllegalStateException("expected failure: $what")
}

// Every field of each failure is compared, as the Swift host compares the whole value.
private fun signerRefusal(failure: SignerFfiException, kind: RefusalKind) =
    failure is SignerFfiException.Refused && failure.kind == kind &&
        listOf(failure.sinceMs, failure.version, failure.toApp, failure.install, failure.stop,
            failure.measurements, failure.alert, failure.scopes).all { it == null }

private fun signerStoreFailure(failure: SignerFfiException, kind: StoreErrorKind) =
    failure is SignerFfiException.Store && failure.kind == kind && failure.size == null && failure.cap == null

private fun signerTimeout(failure: SignerFfiException) =
    failure is SignerFfiException.Service && failure.kind == ServiceFailure.TRANSPORT &&
        failure.transport == TransportFailure.TIMEOUT && !failure.authenticated && !failure.notHosted &&
        listOf(failure.status, failure.code, failure.retryAfterS, failure.retry, failure.knownVersion,
            failure.limit, failure.generation, failure.serverTimeMs, failure.detail).all { it == null }

private fun signerClosed(failure: SignerFfiException) =
    failure is SignerFfiException.InvalidInput && failure.reason == "the signer is closed"

/** End the signer, and check that it is closed: every call after it is refused. */
private suspend fun signerEnd(signer: Signer) {
    signer.shutdown()
    require(signerClosed(signerFailureFrom("status after shutdown") { signer.status() }), "shutdown closed the signer")
}

/** The child holds its newly created signer until the process ends (Switch spec 4.3). */
suspend fun signerHostChild(args: List<String>): Boolean {
    if (args.firstOrNull() != signerChildMarker) return false
    require(args.size == 3 && args.last() == "hold", "signer child arguments")
    val root = Path.of(args[1])
    // The watchdog bounds the whole child, its wait for its parent's word included.
    Watchdog.enter("signer child ${ProcessHandle.current().pid()}: hold")
    registerSampleProtocol()
    FixtureService(seed(), MemoryHomeserver()).use { service ->
        service.createSigner(signerVault(), FileStore(root), signerOrigin).use { signer ->
            // Standard output is the child's channel to its parent: the parent reads this
            // line as the install ID.
            println(Base64.getEncoder().encodeToString(signer.installId()))
            System.out.flush()
            Files.createFile(root.resolve("ready"))
            // EOF frees the signer if its parent exits.
            System.`in`.read()
            signerEnd(signer)
        }
    }
    return true
}

private suspend fun signerEnroll(root: Path) {
    val vault = signerVault()
    FixtureService(seed(), MemoryHomeserver()).use { service ->
        val identity = service.createSigner(vault, FileStore(root), signerOrigin).use { signer ->
            require(signer.status() == SignerStatus.Enrolling, "created signer is enrolling")
            require(service.enrollments() == 0uL, "creation sent no enrollment")
            signer.resume()
            require(signer.status() == SignerStatus.Signing, "resumed signer is signing")
            val identity = signer.identity()
            openKeyring(vault).use { keyring ->
                require(identity.size == 32 && identity.contentEquals(keyring.publicKey()), "signer identity")
            }
            require(signer.installId().size == 16, "install ID length")
            // Neither a status nor the signer's handle describes what it holds.
            val recovering = SignerStatus.Recovering("https://private.example")
            require(recovering.toString() == "SignerStatus(<redacted>)", "a status's description")
            require(!signer.toString().contains(Base64.getEncoder().encodeToString(identity)) &&
                signer.toString().startsWith("pubky.switch.signer.Signer@"), "the signer's description")
            signerEnd(signer)
            identity
        }
        service.openSigner(vault, FileStore(root)).use { reopened ->
            require(reopened.status() == SignerStatus.Signing, "reopened signer is signing")
            require(reopened.identity().contentEquals(identity), "reopened signer's identity")
            signerEnd(reopened)
        }
    }
}

private suspend fun signerInterrupted(root: Path) {
    val vault = signerVault()
    FixtureService(seed(), MemoryHomeserver()).use { service ->
        val install = service.createSigner(vault, FileStore(root), signerOrigin).use { signer ->
            val id = signer.installId()
            service.loseNextEnrollAnswer()
            require(signerTimeout(signerFailureFrom("lost enrollment answer") { signer.resume() }),
                "lost enrollment answer is a transport timeout")
            signerEnd(signer)
            id
        }
        service.openSigner(vault, FileStore(root)).use { reopened ->
            require(reopened.installId().contentEquals(install), "install ID after lost answer")
            reopened.resume()
            require(reopened.status() == SignerStatus.Signing, "resumed interrupted enrollment")
            require(service.enrollments() == 1uL, "one distinct enrollment")
            signerEnd(reopened)
        }
    }
}

private suspend fun signerKilledOwner(root: Path) {
    val java = ProcessHandle.current().info().command().orElseThrow()
    val child = ProcessBuilder(
        java, "-Djna.library.path=" + System.getProperty("jna.library.path"),
        "-cp", System.getProperty("java.class.path"), "pubky.switch.signer.tests.MainKt",
        signerChildMarker, root.toString(), "hold",
    ).redirectError(ProcessBuilder.Redirect.INHERIT).start()
    try {
        val started = System.nanoTime()
        while (!Files.exists(root.resolve("ready"))) {
            require(child.isAlive, "signer child exited before creating")
            require(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(30), "signer child timed out")
            delay(20)
        }
        val vault = signerVault()
        FixtureService(seed(), MemoryHomeserver()).use { service ->
            val busy = signerFailureFrom("live child owns signer") { service.openSigner(vault, FileStore(root)) }
            require(signerStoreFailure(busy, StoreErrorKind.IN_USE), "child owns signer")
            // The marker is written only after the whole line is flushed.
            val install = child.inputStream.bufferedReader().use { Base64.getDecoder().decode(it.readLine()) }
            require(install.size == 16, "child's install ID length")
            // SIGKILL: the child ends without running any of its own code.
            child.destroyForcibly()
            require(child.waitFor(30, TimeUnit.SECONDS) && child.exitValue() == 128 + 9, "signer child killed")

            service.openSigner(vault, FileStore(root)).use { reopened ->
                require(reopened.installId().contentEquals(install), "killed signer's install ID")
                require(reopened.status() == SignerStatus.Enrolling, "killed signer kept its enrollment")
                reopened.resume()
                require(reopened.status() == SignerStatus.Signing, "resumed killed signer")
                signerEnd(reopened)
            }
        }
    } finally {
        if (child.isAlive) child.destroyForcibly()
        require(child.waitFor(30, TimeUnit.SECONDS), "signer child cleanup")
    }
}

private suspend fun signerProduction(root: Path) {
    val vault = signerVault()
    val store = FileStore(root)
    val home = MemoryHomeserver()
    val origin = "https://service.example"
    SignerEnvironment(home, TransportOptions()).use { env ->
        val empty = signerFailureFrom("empty production store") { env.openSigner(vault, store) }
        require(signerRefusal(empty, RefusalKind.NOT_SET_UP), "empty store refusal")
        env.createSigner(vault, store, origin).use { signer ->
            require(signer.status() == SignerStatus.Enrolling, "offline creation")
            signerEnd(signer)
        }
        val existing = signerFailureFrom("existing production store") { env.createSigner(vault, store, origin) }
        require(signerRefusal(existing, RefusalKind.ALREADY_SET_UP), "existing store refusal")
        require(home.calls.isEmpty(), "offline setup made no homeserver call")
    }
}

private suspend fun signerClosedCalls(root: Path) {
    FixtureService(seed(), MemoryHomeserver()).use { service ->
        service.createSigner(signerVault(), FileStore(root), signerOrigin).use { signer ->
            signer.shutdown()
            for (failure in listOf(
                signerFailureFrom("resume after shutdown") { signer.resume() },
                signerFailureFrom("status after shutdown") { signer.status() },
                signerFailureFrom("identity after shutdown") { signer.identity() },
                signerFailureFrom("install ID after shutdown") { signer.installId() },
                signerFailureFrom("second shutdown") { signer.shutdown() },
            )) {
                require(signerClosed(failure), "closed signer refusal")
            }
        }
    }
}

// The last handle goes without a shutdown (here, Kotlin's close of the handle): the signer
// is dropped as it is, its hold on the store's records goes with it, and the next open
// takes them.
private suspend fun signerDropped(root: Path) {
    val vault = signerVault()
    FixtureService(seed(), MemoryHomeserver()).use { service ->
        val signer = service.createSigner(vault, FileStore(root), signerOrigin)
        val install = signer.installId()
        signer.close()
        service.openSigner(vault, FileStore(root)).use { reopened ->
            require(reopened.installId().contentEquals(install), "install ID after a dropped signer")
            require(reopened.status() == SignerStatus.Enrolling, "dropped signer kept its enrollment")
            signerEnd(reopened)
        }
    }
}

// A signer whose handle was lost, as a cancelled call can lose it, holds the store's records
// until the host ends it through the store.
private suspend fun signerLostHandle(root: Path) {
    val vault = signerVault()
    FixtureService(seed(), MemoryHomeserver()).use { service ->
        service.createSignerLosingHandle(vault, FileStore(root), signerOrigin)
        val busy = signerFailureFrom("lost signer owns the store") { service.openSigner(vault, FileStore(root)) }
        require(signerStoreFailure(busy, StoreErrorKind.IN_USE), "lost signer owns the store")
        shutdownSigners(FileStore(root))
        service.openSigner(vault, FileStore(root)).use { reopened ->
            require(reopened.status() == SignerStatus.Enrolling, "the ended signer kept its enrollment")
            shutdownSigners(FileStore(root))
            require(signerClosed(signerFailureFrom("status after the end") { reopened.status() }),
                "ending the store's signers closed the handle")
        }
    }
}

/** Check the signer's life cycle (Switch spec 4.3). */
suspend fun checkSigner() {
    registerSampleProtocol()
    val root = Files.createTempDirectory("signer-lifecycle")
    var completed = 0
    suspend fun run(name: String, check: suspend (Path) -> Unit) {
        val directory = Files.createDirectory(root.resolve(name))
        step("signer: $name") { check(directory) }
        completed += 1
    }
    try {
        run("enroll", ::signerEnroll)
        run("interrupted", ::signerInterrupted)
        run("killed", ::signerKilledOwner)
        run("production", ::signerProduction)
        run("closed", ::signerClosedCalls)
        run("dropped", ::signerDropped)
        run("lost", ::signerLostHandle)
        require(completed == 7, "every signer check ran")
    } finally {
        root.toFile().deleteRecursively()
    }
}
