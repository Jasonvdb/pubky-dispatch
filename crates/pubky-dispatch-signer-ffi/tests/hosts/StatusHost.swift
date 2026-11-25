// The Swift host's checks of the signer's views and settings.
import Foundation
import PubkyDispatchSigner

/// Check the newest version and the signer's settings (Dispatch spec 4.3).
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
            guard let doc = try await signer.identityDoc(), let mark = try await signer.highWater() else {
                check(false, "missing enrolled document or high-water mark")
                return
            }
            verify(doc.generation == 1 && doc.version == 1, "first document")
            verify(doc.recordMaxAge == nil &&
                   doc.connectRequests == ConnectRequestsView(enabled: false, maxPending: 50, push: false),
                   "first document settings")
            verify(mark.generation == 1 && mark.version == 1, "first high-water mark")
            verify(doc.hash.count == 32 && mark.docHash == doc.hash, "high-water document hash")
            verify(doc.bodyHash.count == 32 && mark.bodyHash == doc.bodyHash, "high-water body hash")
            verify(try await signer.apps().isEmpty, "no enrolled apps")
            verify(try await signer.certificates().isEmpty, "no enrolled certificates")

            let limited = try await signer.setRecordMaxAge(seconds: 86_400)
            verify(limited.version == 2 && limited.recordMaxAge == 86_400, "record age set")
            verify(try await signer.identityDoc() == limited, "record age read back")
            do {
                _ = try await signer.setRecordMaxAge(seconds: 0)
                check(false, "zero record age accepted")
            } catch let failure as SignerFfiError {
                verify(failure == .InvalidData(kind: .invalid), "zero record age refused as invalid data")
            }
            verify(try await signer.identityDoc() == limited, "same document after zero record age")

            let settings = ConnectRequestsView(enabled: true, maxPending: 17, push: true)
            let configured = try await signer.setConnectRequests(settings: settings)
            verify(configured.version == 3 && configured.connectRequests == settings &&
                   configured.recordMaxAge == 86_400, "connect request settings set")
            verify(try await signer.identityDoc() == configured, "connect request settings read back")

            let cleared = try await signer.setRecordMaxAge(seconds: nil)
            verify(cleared.version == 4 && cleared.recordMaxAge == nil &&
                   cleared.connectRequests == settings, "record age cleared")
            verify(try await signer.identityDoc() == cleared, "cleared record age read back")
            try await signerEnd(signer)
        }
        check(completed == 17, "every status check ran")
    } catch {
        check(false, "unexpected signer status failure")
    }
}
