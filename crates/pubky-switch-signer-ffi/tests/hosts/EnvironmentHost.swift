// Host checks for the signer environment and protocol authority (Switch spec 3.2).
import Foundation
import PubkySwitchSigner

private actor MemoryHomeserver: HostHomeserver {
    private let denied: Bool
    private var files: [String: Data] = [:]
    private(set) var calls: [String] = []
    private(set) var written: Data?

    init(denied: Bool = false) { self.denied = denied }

    func get(path: String) async throws -> Data? {
        calls.append("get \(path)")
        if denied { throw HomeserverFailure.Denied }
        return files[path]
    }

    func put(path: String, bytes: Data) async throws {
        calls.append("put \(path)")
        files[path] = bytes
        written = bytes
    }

    func delete(path: String) async throws {
        calls.append("delete \(path)")
        files.removeValue(forKey: path)
    }
}

private func refusal(_ kind: RefusalKind, toApp: Data? = nil, stop: KeyRecoveryStopKind? = nil,
                     measurements: RefusalMeasurements? = nil, scopes: [String]? = nil) -> SignerFfiError {
    .Refused(kind: kind, sinceMs: nil, version: nil, toApp: toApp, install: nil,
             stop: stop, measurements: measurements, alert: nil,
             scopes: scopes.map { UnownedScopes(names: $0) })
}

private func serviceFailure(_ kind: ServiceFailure, status: UInt16? = nil, authenticated: Bool,
                            code: String? = nil, retryAfterS: UInt64? = nil, retry: RetryKind? = nil,
                            transport: TransportFailure? = nil, limit: UInt64? = nil) -> SignerFfiError {
    .Service(kind: kind, status: status, authenticated: authenticated, code: code, retryAfterS: retryAfterS,
             retry: retry, notHosted: false, knownVersion: nil, transport: transport, limit: limit,
             generation: nil, serverTimeMs: nil, detail: nil)
}

private func checkSampleFailures() throws {
    let cases: [(SampleFailure, SignerFfiError)] = [
        (.clockOff, refusal(.clockOff, measurements: .clockOff(deviceMs: 5, serviceMs: 9))),
        (.handingOver, refusal(.handingOver, toApp: Data(repeating: 3, count: 16))),
        (.keyRecovery, refusal(.keyRecovery, stop: .serviceBehind,
                              measurements: .serviceBehind(serviceVersion: 2, seenVersion: 4))),
        (.storeTooLarge, .Store(kind: .tooLarge, size: 13, cap: 12)),
        (.transportTooLarge, serviceFailure(.transport, authenticated: false, transport: .tooLarge, limit: 64)),
        (.errorAnswer, serviceFailure(.errorAnswer, status: 429, authenticated: true, code: "rate_limited",
                                       retryAfterS: 37, retry: .afterRetryAfter)),
        (.bodyUnread, serviceFailure(.bodyUnread, status: 429, authenticated: true, code: "rate_limited", retryAfterS: 19)),
        (.unsignedStatus, serviceFailure(.badServiceSignature, status: 404, authenticated: false)),
        (.undecodable, .Records(kind: .undecodable, record: .flow, line: 7, column: 11, write: nil, size: nil, cap: nil)),
        (.notNamed, .NotNamed(install: Data(repeating: 5, count: 16))),
        (.handedOver, .HandedOver(install: Data(repeating: 7, count: 16))),
        (.invalidData, .InvalidData(kind: .invalid)),
        (.storedData, .StoredData(kind: .invalid)),
        (.alarm, .Alarm(alert: .backupUnreadable)),
    ]
    for (sample, expected) in cases {
        do {
            try sampleFailure(sample: sample)
            check(false, "expected a signer failure")
        } catch let failure as SignerFfiError {
            check(failure == expected, "wrong typed fields for \(sample)")
            check(!String(reflecting: failure).contains(fixtureText) &&
                  !failure.localizedDescription.contains(fixtureText), "inner error text crossed the binding")
        }
    }
}

/// Check the environment, scope terms and signer errors (Switch spec 3.2).
func checkEnvironment() async {
    do {
        try registerSampleProtocol()
        try registerSampleProtocol()
        check(try protocolNames() == ["sample"], "registered protocol names")
        let terms = try scopeTerms(scopes: ["sample-a"])
        check(terms.keyed == ["sample-a"] && terms.permissions == ["claims.read"], "sample authority")
        // A scope no registered protocol owns, with a sub-scope label another app chose.
        let unowned = "elsewhere:private-label"
        for (scope, expected) in [("sample-b", refusal(.protocolRule)),
                                  (unowned, refusal(.unknownScopes, scopes: [unowned]))] {
            do {
                _ = try scopeTerms(scopes: [scope])
                check(false, "expected a scope refusal")
            } catch let failure as SignerFfiError {
                check(failure == expected, "scope refusal")
                // The field holds the name; the error's text never does.
                check(!String(reflecting: failure).contains("private-label") &&
                      !String(describing: failure).contains("private-label") &&
                      !failure.localizedDescription.contains("private-label"),
                      "a refused scope's name crossed in the error text")
            }
        }
        try checkSampleFailures()

        let home = MemoryHomeserver()
        _ = try SignerEnvironment(homeserver: home, transport: TransportOptions())
        do {
            _ = try SignerEnvironment(homeserver: home, transport: TransportOptions(requestTimeoutMs: 0))
            check(false, "accepted a zero timeout")
        } catch SignerFfiError.InvalidInput(let reason) {
            check(reason == "request_timeout_ms", "zero timeout field")
        }

        let path = "/sample"
        let bytes = Data([0, 255, 3])
        let trip = try await homeserverRoundTrip(homeserver: home, path: path, bytes: bytes)
        check(trip.absentBefore && trip.matchedAfterPut && trip.absentAfter, "homeserver round trip")
        check(await home.written == bytes, "host received the supplied bytes")
        let expected = ["get", "put", "get", "delete", "delete", "get"].map { "\($0) \(path)" }
        check(await home.calls == expected, "homeserver calls")
        let denied = MemoryHomeserver(denied: true)
        do {
            _ = try await homeserverRoundTrip(homeserver: denied, path: path, bytes: bytes)
            check(false, "denied read reported absence")
        } catch let failure as SignerFfiError {
            check(failure == .Homeserver(kind: .refused, size: nil, status: nil), "denied read")
        }
        check(await denied.calls == ["get \(path)"], "denial stopped the round trip")
    } catch {
        check(false, "unexpected environment failure")
    }
}
