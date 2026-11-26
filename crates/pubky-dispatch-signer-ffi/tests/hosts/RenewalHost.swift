// The Swift host's checks of renewing an app's certificate.
import Foundation
import PubkyDispatchSigner

/// Check the renewal of an app's certificate (Dispatch spec 3.2).
func checkRenewal() async {
    var completed = 0
    func verify(_ condition: Bool, _ what: String) {
        check(condition, what)
        completed += 1
    }

    do {
        try registerSampleProtocol()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = MemoryVault()
        vault.importSeed()
        try await step("renewal: renew, reduce and renew the expiring") {
            let fixture = try FixtureApps(seed: seed(), homeserver: MemoryHomeserver())
            let signer = try await fixture.signerWithApps(vault: vault, store: FileStore(root),
                                                          origin: "https://dispatch.example", apps: 2)
            func app(_ id: Data) async throws -> AppSummaryView {
                guard let found = try await signer.apps().first(where: { $0.appId == id }) else {
                    fatalError("missing joined app")
                }
                return found
            }

            let ids = fixture.appIds()
            verify(ids.count == 2 && ids.allSatisfy { $0.count == 16 } && ids.first != ids.last,
                   "two distinct app IDs")
            let first = ids[0], second = ids[1]
            guard let old = try await app(first).cert, let before = try await signer.identityDoc() else {
                fatalError("missing original certificate or identity document")
            }
            let scopes = ["sample-a", "sample-b"]
            let secondCert = try await app(second).cert
            verify(old.scopes == scopes && secondCert?.scopes == scopes, "both apps have both scopes")

            let day: UInt64 = 86_400_000
            let later = old.expiresAt + day
            let renewed = try await signer.renew(appId: first, change: CertChangeView(scopes: nil, expiresAt: later))
            let published = try await signer.identityDoc()
            verify(renewed.version == before.version + 1 && published == renewed,
                   "the returned version is the newest version")
            let open = try await app(first)
            guard let cert = open.cert else { fatalError("missing renewed certificate") }
            verify(cert.hash != old.hash && open.listedCert == cert.hash &&
                   cert.expiresAt == later && cert.scopes == old.scopes, "new listed certificate with the requested expiry")
            verify(open.renewalOpen, "expiry extension is open")
            verify(try await signer.completeRenewals().isEmpty, "no closure before take-up")
            verify(try await app(first).renewalOpen, "renewal is still open after the check")
            try fixture.takeUpRenewal(appId: first)
            verify(try await signer.completeRenewals() == [first], "only the app that took up its renewal closed")
            verify(try await !app(first).renewalOpen, "the app's renewal is closed")

            let kept = ["sample-a"]
            let terms = try scopeTerms(scopes: kept)
            verify(terms.keyed == kept && terms.permissions == ["claims.read"], "terms of the kept scope")
            guard let previous = try await signer.identityDoc() else { fatalError("missing version before reduction") }
            let change = CertChangeView(scopes: kept, expiresAt: nil)
            verify(String(reflecting: change) == "CertChangeView(<redacted>)" && Mirror(reflecting: change).children.isEmpty,
                   "the change's debug description and reflection hide its scopes")
            let reduction = try await signer.renew(appId: second, change: change)
            let closing = try await signer.identityDoc()
            verify(reduction.version == previous.version + 1 && closing?.version == reduction.version + 1,
                   "the reduction returns the renewing version and delivers its closing version")
            let reduced = try await app(second)
            verify(reduced.cert?.scopes == kept && reduced.cert?.permissions == terms.permissions && !reduced.renewalOpen,
                   "the other app keeps only the requested scope and its permissions")
            do {
                _ = try await signer.renew(appId: Data(count: 16), change: CertChangeView(scopes: nil, expiresAt: nil))
                check(false, "unknown app was renewed")
            } catch SignerFfiError.Refused(let kind, _, _, _, _, _, _, _, _) {
                verify(kind == .notListed, "unknown app has the not-listed refusal")
            }

            verify(try await signer.renewExpiring().isEmpty, "neither certificate is due yet")
            fixture.advanceTimeMs(by: (later - old.issuedAt) / 2 + day)
            let automatic = try await signer.renewExpiring()
            verify(automatic.count == ids.count && Set(automatic) == Set(ids),
                   "both apps past half their certificate lifetime were renewed")
            verify(try await signer.renewExpiring().isEmpty, "the next call renews neither app again")
            try await signerEnd(signer)
        }
        check(completed == 17, "every renewal check ran")
    } catch {
        check(false, "unexpected signer renewal failure")
    }
}
