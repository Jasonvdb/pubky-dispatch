// A Kotlin host of the signer bindings: it awaits one call, catches one typed failure, and
// checks that no generated description or error text shows the secret it handed over.
package pubky.switch.signer.tests

import kotlinx.coroutines.runBlocking
import pubky.switch.signer.FixtureFailure
import pubky.switch.signer.HostSecret
import pubky.switch.signer.KeyFailure
import pubky.switch.signer.SignerFfiException
import pubky.switch.signer.publicIdentityOf
import pubky.switch.signer.redactionFixture
import pubky.switch.signer.redactionFixtureFailure
import pubky.switch.signer.signerFfiVersion

// The first identity of the Switch's key vectors (spec/vectors/keys.json): a fixed test
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

fun main() = runBlocking {
    require(signerFfiVersion().isNotEmpty(), "a version")
    val secret = HostSecret(seed())
    require(!showsSeed(secret.toString()), "the secret's description")
    val identity = publicIdentityOf(secret)
    require(identity.pubkyId == PUBKY_ID, "the vector's Pubky ID")
    require(identity.publicKey.size == 32, "a 32-byte public key")
    val short = seed().copyOf(31)
    try {
        publicIdentityOf(HostSecret(short))
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
    println("signer bindings: Kotlin host passed")
}
