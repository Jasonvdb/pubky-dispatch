// A Kotlin host of the signer bindings: it awaits one call, catches one typed failure, and
// checks that no generated description or error text shows the secret it handed over.
package pubky.dispatch.signer.tests

import kotlinx.coroutines.runBlocking
import pubky.dispatch.signer.FixtureFailure
import pubky.dispatch.signer.HostSecret
import pubky.dispatch.signer.KeyFailure
import pubky.dispatch.signer.SignerFfiException
import pubky.dispatch.signer.redactionFixture
import pubky.dispatch.signer.redactionFixtureFailure
import pubky.dispatch.signer.signerFfiVersion

// The first identity of the Dispatch's key vectors (spec/vectors/keys.json): a fixed test
// seed, never a generated or real one.
const val SEED_HEX = "f6986ca57be738d68145e3c06ef2d1dc3025952fc2be9d6246c6497410519142"
const val PUBKY_ID = "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo"

// The text the redaction fixtures carry (the crate's `FIXTURE_TEXT`).
const val FIXTURE_TEXT = "fixture-text-not-to-show"

fun seed(): ByteArray = SEED_HEX.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun require(condition: Boolean, what: String) {
    if (!condition) throw IllegalStateException(what)
}

// What a description of the seed would show: its hex or its bytes.
fun showsSeed(text: String): Boolean =
    text.contains(SEED_HEX.substring(0, 16)) || text.contains(seed().take(4).joinToString(", "))

fun main(args: Array<String>) = runBlocking {
    if (storeHostChild(args.toList())) return@runBlocking
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
    checkVault()
    checkStore()
    checkEnvironment()
    println("signer bindings: Kotlin host passed")
}
