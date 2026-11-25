// The Swift host's checks of the signer's alerts.
import Foundation
import PubkyDispatchSigner

/// Check the signer's alerts (Dispatch spec 4.3).
func checkAlerts() async {
    var completed = 0
    func verify(_ condition: Bool, _ what: String) {
        check(condition, what)
        completed += 1
    }

    func onlyRollback(_ alerts: [SeenAlert]) -> SeenAlert {
        verify(alerts.count == 1, "one uncleared alert")
        guard let alert = alerts.first,
              case let .rollback(source, version, generation, highWaterVersion) = alert.facts() else {
            fatalError("expected a rollback")
        }
        verify(source == .service, "rollback at the service")
        verify(version == nil, "missing copy has no version")
        verify(generation == nil, "missing copy has no generation")
        verify(highWaterVersion == 1, "enrollment is the high-water version")
        return alert
    }

    do {
        try registerSampleProtocol()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = MemoryVault()
        vault.importSeed()
        try await step("alerts: a lost copy") {
            let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
            let signer = try await service.createSigner(vault: vault, store: FileStore(root),
                                                        origin: "https://dispatch.example")
            try await signer.resume()
            verify(try signer.status() == .signing, "signer enrolled")
            verify(try await signer.alerts().isEmpty, "enrollment left no alerts")
            service.loseIdentity()
            let setting: Bool
            do {
                _ = try await signer.setRecordMaxAge(seconds: 3_600)
                setting = true
            } catch SignerFfiError.Alarm(let kind) {
                setting = kind == .rollback
            }
            verify(setting, "setting completed or raised the rollback")

            let alert = onlyRollback(try await signer.alerts())
            verify(try !alert.namesApp(appId: Data(count: 16)), "identity rollback names no app")
            do {
                _ = try alert.namesApp(appId: Data(count: 15))
                check(false, "short app ID was accepted")
            } catch SignerFfiError.InvalidInput {
                verify(true, "short app ID is invalid input")
            }
            do {
                try await alert.clear()
                check(false, "clearing the lost copy succeeded")
            } catch SignerFfiError.Alarm(let kind) {
                verify(kind == .rollback, "clearing the lost copy raised the rollback again")
            }

            let kept = onlyRollback(try await signer.alerts())
            verify(try signer.status() == .alarm, "signer still stands at alarm")
            try await signerEnd(signer)
            // An alert kept past its signer's end still reads, and clears nothing.
            if case .rollback = kept.facts() {
                verify(true, "a kept alert still reads")
            } else {
                check(false, "a kept alert still reads")
            }
            do {
                try await kept.clear()
                check(false, "a kept alert cleared")
            } catch SignerFfiError.InvalidInput(let reason) {
                verify(reason == "the signer is closed", "a kept alert's clear is refused as closed")
            }
        }
        check(completed == 19, "every alert check ran")
    } catch {
        check(false, "unexpected signer alert failure")
    }
}
