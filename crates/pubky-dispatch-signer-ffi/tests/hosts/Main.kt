// A Kotlin host of the signer bindings: it awaits one call, catches one typed failure, and
// checks that no generated description or error text shows the secret it handed over.
package pubky.dispatch.signer.tests

import com.sun.jna.Native
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import pubky.dispatch.signer.FixtureCallback
import pubky.dispatch.signer.FixtureCallbackAsync
import pubky.dispatch.signer.FixtureCallbackFailure
import pubky.dispatch.signer.FixtureCallbackOutcome
import pubky.dispatch.signer.FixtureFailure
import pubky.dispatch.signer.HostSecret
import pubky.dispatch.signer.KeyFailure
import pubky.dispatch.signer.SignerFfiException
import pubky.dispatch.signer.fixtureCallbackAsyncOutcome
import pubky.dispatch.signer.fixtureCallbackOutcome
import pubky.dispatch.signer.redactionFixture
import pubky.dispatch.signer.redactionFixtureFailure
import pubky.dispatch.signer.signerFfiVersion

// The first identity of the Dispatch's key vectors (spec/vectors/keys.json): a fixed test
// seed, never a generated or real one.
const val SEED_HEX = "f6986ca57be738d68145e3c06ef2d1dc3025952fc2be9d6246c6497410519142"
const val PUBKY_ID = "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo"

// The text the redaction fixtures carry (the crate's `FIXTURE_TEXT`).
const val FIXTURE_TEXT = "fixture-text-not-to-show"

// What Rust is handed in place of the text of what a host callback threw.
const val CALLBACK_FAILURE = "a host callback failed"

fun seed(): ByteArray = SEED_HEX.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun require(condition: Boolean, what: String) {
    if (!condition) throw IllegalStateException(what)
}

// What a description of the seed would show: its hex or its bytes.
fun showsSeed(text: String): Boolean =
    text.contains(SEED_HEX.substring(0, 16)) || text.contains(seed().take(4).joinToString(", "))

// Host callbacks that throw what they were given, or return, and count their calls.
class ThrowingCallback(private val thrown: Throwable?, private val calls: AtomicInteger) : FixtureCallback {
    override fun call() {
        calls.incrementAndGet()
        thrown?.let { throw it }
    }
}

class ThrowingCallbackAsync(private val thrown: Throwable?, private val calls: AtomicInteger) : FixtureCallbackAsync {
    override suspend fun call() {
        calls.incrementAndGet()
        thrown?.let { throw it }
    }
}

// A callback that fails is read as failed whatever it throws, an `Error` as much as an
// `Exception` and a typed failure the bindings can't lower, and Rust is handed a fixed text
// in place of what it threw. What isn't an `Exception` is still reported on the host's side.
suspend fun checkCallbackFailures() {
    val synchronous = AtomicInteger()
    val asynchronous = AtomicInteger()
    // How Rust read the end of a synchronous and of an asynchronous callback throwing
    // `thrown`. An asynchronous callback Rust is left waiting for has no outcome.
    suspend fun outcomes(thrown: () -> Throwable?): List<FixtureCallbackOutcome?> = listOf(
        fixtureCallbackOutcome(ThrowingCallback(thrown(), synchronous)),
        withTimeoutOrNull(60_000) {
            fixtureCallbackAsyncOutcome(ThrowingCallbackAsync(thrown(), asynchronous))
        },
    )
    // Where the platform reports what a callback threw: JNA's handler for a synchronous
    // callback, the thread's for an asynchronous one's coroutine.
    val reported = CopyOnWriteArrayList<Throwable>()
    val jnaHandler = Native.getCallbackExceptionHandler()
    val threadHandler = Thread.getDefaultUncaughtExceptionHandler()
    Native.setCallbackExceptionHandler { _, thrown -> reported.add(thrown) }
    Thread.setDefaultUncaughtExceptionHandler { _, thrown -> reported.add(thrown) }
    try {
        for (outcome in outcomes { null }) {
            require(outcome == FixtureCallbackOutcome.Returned, "a callback that returns")
        }
        for (outcome in outcomes { FixtureCallbackFailure.Refused() }) {
            require(outcome == FixtureCallbackOutcome.Refused, "a callback's typed failure")
        }
        // Each with whether it is thrown on once Rust has its failure.
        val unexpected = listOf<Triple<String, Boolean, () -> Throwable>>(
            Triple("an Exception", false) { IllegalStateException(FIXTURE_TEXT) },
            Triple("an AssertionError", true) { AssertionError(FIXTURE_TEXT) },
            Triple("an OutOfMemoryError", true) { OutOfMemoryError(FIXTURE_TEXT) },
            Triple("a Throwable", true) { object : Throwable(FIXTURE_TEXT) {} },
            // A lone surrogate isn't valid Unicode: the failure's text can't be encoded.
            Triple("an unencodable failure", false) { FixtureCallbackFailure.Unexpected("\uD800") },
        )
        var thrownOn = 0
        for ((what, rethrown, thrown) in unexpected) {
            for (outcome in outcomes(thrown)) {
                val reason = (outcome as? FixtureCallbackOutcome.Unexpected)?.reason
                    ?: throw IllegalStateException(
                        "a callback that threw $what was read as ${outcome?.javaClass?.simpleName}",
                    )
                require(reason == CALLBACK_FAILURE, "the text of $what a callback threw")
            }
            if (rethrown) thrownOn += 2
            // The asynchronous callback's thread reports on its own time.
            withTimeoutOrNull(60_000) { while (reported.size < thrownOn) delay(10) }
            require(reported.size == thrownOn, "$what a callback threw, reported to the host")
        }
        // A host's own handler may throw. JNA writes the call's status back only after
        // the handler returns, so the failure has to be with Rust before the error is
        // thrown on.
        Native.setCallbackExceptionHandler { _, _ -> throw IllegalStateException("the handler failed") }
        val unhandled = fixtureCallbackOutcome(ThrowingCallback(AssertionError(FIXTURE_TEXT), synchronous))
        require(
            (unhandled as? FixtureCallbackOutcome.Unexpected)?.reason == CALLBACK_FAILURE,
            "an error thrown past a handler that throws was read as ${unhandled.javaClass.simpleName}",
        )
        val calls = 2 + unexpected.size
        require(synchronous.get() == calls + 1, "every synchronous callback check ran")
        require(asynchronous.get() == calls, "every asynchronous callback check ran")
    } finally {
        Native.setCallbackExceptionHandler(jnaHandler)
        Thread.setDefaultUncaughtExceptionHandler(threadHandler)
    }
}

fun main(args: Array<String>) = runBlocking {
    Watchdog.start("starting")
    if (storeHostChild(args.toList())) return@runBlocking
    step("the secret's handle and its redaction") { checkSecret() }
    step("callback failures") { checkCallbackFailures() }
    step("vault") { checkVault() }
    checkStore()
    step("environment") { checkEnvironment() }
    println("signer bindings: Kotlin host passed")
}

// The secret's handle refuses a second use, a close and a short seed, and nothing shows
// the secret.
suspend fun checkSecret() {
    require(signerFfiVersion().isNotEmpty(), "a version")
    val secret = HostSecret(seed())
    require(!showsSeed(secret.toString()), "the secret's description")
    val identity = secret.publicIdentity()
    require(identity.pubkyId == PUBKY_ID, "the vector's Pubky ID")
    require(identity.publicKey.size == 32, "a 32-byte public key")
    // Used up: a second use is the typed refusal.
    try {
        secret.publicIdentity()
        throw IllegalStateException("a used secret was taken again")
    } catch (refused: SignerFfiException.InvalidInput) {
        require(!showsSeed(refused.toString()), "the refusal's text")
    }
    // Closed by the host: the bindings refuse it, and nothing reaches Rust.
    val closed = HostSecret(seed())
    closed.close()
    try {
        closed.publicIdentity()
        throw IllegalStateException("a closed secret was used")
    } catch (refused: IllegalStateException) {
        require(refused.message.orEmpty().contains("destroyed"), "the closed handle's refusal")
    }
    HostSecret(seed()).use { inside -> require(inside.publicIdentity().pubkyId == PUBKY_ID, "use") }
    val short = seed().copyOf(31)
    try {
        HostSecret(short).publicIdentity()
        throw IllegalStateException("a short secret was taken")
    } catch (refused: SignerFfiException.Key) {
        require(refused.kind == KeyFailure.MALFORMED, "a malformed secret")
        for (text in listOf(refused.toString(), refused.message.orEmpty())) {
            require(!showsSeed(text), "the error's text")
        }
    }
    // A value and an error off the public list are described as redacted only.
    val fixture = redactionFixture()
    require(fixture.hidden == FIXTURE_TEXT, "the fixture's text")
    require(fixture.toString() == "RedactionFixture(<redacted>)", "the record's description")
    try {
        redactionFixtureFailure()
        throw IllegalStateException("the fixture failure wasn't thrown")
    } catch (failure: FixtureFailure.Hidden) {
        require(failure.hidden == FIXTURE_TEXT, "the failure's text")
        require(failure.toString() == "FixtureFailure(<redacted>)", "the error's description")
        require(failure.message == "FixtureFailure(<redacted>)", "the error's message")
    }
}
