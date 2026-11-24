// A Swift host of the signer bindings: it awaits one call, catches one typed failure, and
// checks that no generated description or error text shows the secret it handed over.
import Foundation
import PubkySwitchSigner

// The first identity of the Switch's key vectors (spec/vectors/keys.json): a fixed test
// seed, never a generated or real one.
let seedHex = "f6986ca57be738d68145e3c06ef2d1dc3025952fc2be9d6246c6497410519142"
let pubkyId = "8y3qy4g9q7y9ownd18hskdoxdxzueutiu3f391rnnuxznxmqp5bo"

// The text the redaction fixtures carry (the crate's `FIXTURE_TEXT`).
let fixtureText = "fixture-text-not-to-show"

// What Rust is handed in place of the text of what a host callback threw.
let callbackFailure = "a host callback failed"

func seed() -> Data {
    var bytes = Data()
    var at = seedHex.startIndex
    while at < seedHex.endIndex {
        let next = seedHex.index(at, offsetBy: 2)
        bytes.append(UInt8(seedHex[at..<next], radix: 16)!)
        at = next
    }
    return bytes
}

func check(_ condition: Bool, _ what: String) {
    if !condition {
        FileHandle.standardError.write("failed: \(what)\n".data(using: .utf8)!)
        exit(1)
    }
}

// Host callbacks that throw what they were given, or return.
final class ThrowingCallback: FixtureCallback {
    private let thrown: (any Error & Sendable)?

    init(_ thrown: (any Error & Sendable)?) {
        self.thrown = thrown
    }

    func call() throws {
        if let thrown {
            throw thrown
        }
    }
}

final class ThrowingCallbackAsync: FixtureCallbackAsync {
    private let thrown: (any Error & Sendable)?

    init(_ thrown: (any Error & Sendable)?) {
        self.thrown = thrown
    }

    func call() async throws {
        if let thrown {
            throw thrown
        }
    }
}

// An error of the host's own, carrying a text.
struct HostFailure: Error {
    let text: String
}

// How Rust read the end of a synchronous and of an asynchronous callback throwing `thrown`.
func callbackOutcomes(_ thrown: (any Error & Sendable)?) async -> [FixtureCallbackOutcome] {
    let asynchronous = ThrowingCallbackAsync(thrown)
    guard let awaited = try? await fixtureCallbackAsyncOutcome(callback: asynchronous) else {
        check(false, "the asynchronous callback's outcome")
        return []
    }
    return [fixtureCallbackOutcome(callback: ThrowingCallback(thrown)), awaited]
}

// A callback that fails is read as failed whatever it throws, and Rust is handed a fixed
// text in place of what it threw.
func checkCallbackFailures() async {
    for outcome in await callbackOutcomes(nil) {
        check(outcome == .returned, "a callback that returns")
    }
    for outcome in await callbackOutcomes(FixtureCallbackFailure.Refused) {
        check(outcome == .refused, "a callback's typed failure")
    }
    for outcome in await callbackOutcomes(HostFailure(text: fixtureText)) {
        guard case .unexpected(let reason) = outcome else {
            check(false, "a callback's untyped failure")
            return
        }
        check(reason == callbackFailure, "the text of what a callback threw")
    }
}

@main
struct Main {
    static func main() async {
        if await storeHostChild(Array(CommandLine.arguments.dropFirst())) {
            return
        }
        let shown = String(seedHex.prefix(16))
        check(!signerFfiVersion().isEmpty, "a version")
        guard let secret = try? HostSecret(bytes: seed()) else {
            check(false, "the vector seed's handle")
            return
        }
        let bytes = seed().prefix(4).map(String.init).joined(separator: ", ")
        for text in [String(describing: secret), String(reflecting: secret)] {
            check(!text.contains(shown) && !text.contains(bytes), "the secret's description")
        }
        do {
            let identity = try await secret.publicIdentity()
            check(identity.pubkyId == pubkyId, "the vector's Pubky ID")
            check(identity.publicKey.count == 32, "a 32-byte public key")
        } catch {
            check(false, "the vector seed was refused")
        }
        // Used up: a second use is the typed refusal.
        do {
            _ = try await secret.publicIdentity()
            check(false, "a used secret was taken again")
        } catch SignerFfiError.InvalidInput {
        } catch {
            check(false, "an untyped refusal of a used secret")
        }
        do {
            _ = try await HostSecret(bytes: seed().prefix(31)).publicIdentity()
            check(false, "a short secret was taken")
        } catch SignerFfiError.Key(let kind) {
            check(kind == .malformed, "a malformed secret")
        } catch {
            check(false, "an untyped failure")
        }
        do {
            _ = try await HostSecret(bytes: seed().prefix(31)).publicIdentity()
        } catch {
            for text in [String(describing: error), String(reflecting: error), "\(error)",
                         error.localizedDescription] {
                check(!text.contains(shown) && !text.contains(bytes), "the error's text")
            }
        }
        // A value and an error off the public list are described as redacted only.
        let fixture = redactionFixture()
        check(fixture.hidden == fixtureText, "the fixture's text")
        check(String(describing: fixture) == "RedactionFixture(<redacted>)", "the record's description")
        check(String(reflecting: fixture) == "RedactionFixture(<redacted>)", "the record's debug description")
        check(Mirror(reflecting: fixture).children.isEmpty, "the record's reflection")
        do {
            try redactionFixtureFailure()
            check(false, "the fixture failure wasn't thrown")
        } catch let failure as FixtureFailure {
            check(String(describing: failure) == "FixtureFailure(<redacted>)", "the error's description")
            check(String(reflecting: failure) == "FixtureFailure(<redacted>)", "the error's debug description")
            check(!failure.localizedDescription.contains(fixtureText), "the error's localized description")
            check(Mirror(reflecting: failure).children.isEmpty, "the error's reflection")
        } catch {
            check(false, "an untyped fixture failure")
        }
        await checkCallbackFailures()
        await checkVault()
        await checkStore()
        await checkEnvironment()
        print("signer bindings: Swift host passed")
    }
}
