// The Swift host's checks of the signer's views and settings.
import Foundation
import PubkyDispatchSigner

/// Whether the high-water mark is that of `doc`.
private func statusMarks(_ mark: HighWaterView?, _ doc: IdentityDocView) -> Bool {
    guard let mark else { return false }
    return mark.generation == doc.generation && mark.version == doc.version &&
        mark.docHash == doc.hash && mark.bodyHash == doc.bodyHash
}

/// Check the newest version, the signer's settings and its apps (Dispatch spec 3.2, 4.3).
func checkStatus() async {
    var completed = 0
    func verify(_ condition: Bool, _ what: String) {
        check(condition, what)
        completed += 1
    }

    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    do {
        try registerSampleProtocol()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = MemoryVault()
        vault.importSeed()
        try await step("status: views and settings") {
            let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
            let signer = try await service.createSigner(vault: vault, store: FileStore(root), origin: "https://dispatch.example")
            verify(try await signer.identityDoc() == nil, "no document before enrollment")
            verify(try await signer.highWater() == nil, "no high-water mark before enrollment")
            try await signer.resume()
            guard let doc = try await signer.identityDoc() else {
                check(false, "missing enrolled document")
                return
            }
            verify(doc.generation == 1 && doc.version == 1, "first document")
            verify(doc.recordMaxAge == nil &&
                   doc.connectRequests == ConnectRequestsView(enabled: false, maxPending: 50, push: false),
                   "first document settings")
            verify(doc.hash.count == 32 && doc.bodyHash.count == 32 && doc.hash != doc.bodyHash,
                   "a document hash and a body hash, which differ")
            verify(statusMarks(try await signer.highWater(), doc), "the high-water mark is the first document's")
            verify(try await signer.apps().isEmpty, "no enrolled apps")
            verify(try await signer.certificates().isEmpty, "no enrolled certificates")

            let limited = try await signer.setRecordMaxAge(seconds: 86_400)
            verify(limited.version == 2 && limited.recordMaxAge == 86_400, "record age set")
            verify(limited.hash != doc.hash && limited.bodyHash != doc.bodyHash, "a new version has new hashes")
            verify(try await signer.identityDoc() == limited, "record age read back")
            verify(statusMarks(try await signer.highWater(), limited), "the high-water mark follows the new version")
            do {
                _ = try await signer.setRecordMaxAge(seconds: 0)
                check(false, "zero record age accepted")
            } catch let failure as SignerFfiError {
                verify(failure == .InvalidData(kind: .invalid), "zero record age refused as invalid data")
            }
            verify(try await signer.identityDoc() == limited, "same document after zero record age")

            // The two flags differ, so a swap of them shows.
            let settings = ConnectRequestsView(enabled: true, maxPending: 17, push: false)
            let configured = try await signer.setConnectRequests(settings: settings)
            verify(configured.version == 3 && configured.connectRequests.enabled &&
                   !configured.connectRequests.push && configured.connectRequests.maxPending == 17 &&
                   configured.recordMaxAge == 86_400, "connect request settings set")
            verify(try await signer.identityDoc() == configured, "connect request settings read back")

            let cleared = try await signer.setRecordMaxAge(seconds: nil)
            verify(cleared.version == 4 && cleared.recordMaxAge == nil &&
                   cleared.connectRequests == settings, "record age cleared")
            verify(try await signer.identityDoc() == cleared, "cleared record age read back")

            // A known app: the lists show it, with its certificate.
            let appId = try await signer.fixtureApproveSampleApp()
            let apps = try await signer.apps()
            verify(apps.count == 1 && apps[0].appId == appId && apps[0].standing == .listed,
                   "the approved app is listed")
            guard let cert = apps.first?.cert else {
                check(false, "the listed app's certificate")
                return
            }
            verify(cert.appId == appId && apps[0].listedCert == cert.hash &&
                   cert.scopes == ["sample-a:private-label"], "the listed app's certificate")
            let certs = try await signer.certificates()
            verify(certs.count == 1 && certs[0].hash == cert.hash, "the signer keeps its certificate")
            try await signerEnd(signer)
        }
        check(completed == 21, "every status check ran")
    } catch {
        check(false, "unexpected signer status failure")
    }
}
