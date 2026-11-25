// The Kotlin host's checks of the signer's views and settings.
package pubky.dispatch.signer.tests

import java.nio.file.Files
import pubky.dispatch.signer.*

private fun statusSameDoc(read: IdentityDocView?, expected: IdentityDocView): Boolean =
    read != null && read.generation == expected.generation && read.version == expected.version &&
        read.hash.contentEquals(expected.hash) && read.bodyHash.contentEquals(expected.bodyHash) &&
        read.recordMaxAge == expected.recordMaxAge && read.connectRequests == expected.connectRequests

/** Whether the high-water mark is that of `doc`. */
private fun statusMarks(mark: HighWaterView?, doc: IdentityDocView): Boolean =
    mark != null && mark.generation == doc.generation && mark.version == doc.version &&
        mark.docHash.contentEquals(doc.hash) && mark.bodyHash.contentEquals(doc.bodyHash)

/** Check the newest version, the signer's settings and its apps (Dispatch spec 3.2, 4.3). */
suspend fun checkStatus() {
    var completed = 0
    fun verify(condition: Boolean, what: String) {
        require(condition, what)
        completed += 1
    }

    registerSampleProtocol()
    val root = Files.createTempDirectory("signer-status")
    try {
        val vault = MemoryVault().also { it.import() }
        step("status: views and settings") {
            FixtureService(seed(), MemoryHomeserver()).use { service ->
                service.createSigner(vault, FileStore(root), "https://dispatch.example").use { signer ->
                    verify(signer.identityDoc() == null, "no document before enrollment")
                    verify(signer.highWater() == null, "no high-water mark before enrollment")
                    signer.resume()
                    val doc = checkNotNull(signer.identityDoc()) { "missing enrolled document" }
                    verify(doc.generation == 1uL && doc.version == 1uL, "first document")
                    verify(doc.recordMaxAge == null &&
                        doc.connectRequests == ConnectRequestsView(enabled = false, maxPending = 50uL, push = false),
                        "first document settings")
                    verify(doc.hash.size == 32 && doc.bodyHash.size == 32 && !doc.hash.contentEquals(doc.bodyHash),
                        "a document hash and a body hash, which differ")
                    verify(statusMarks(signer.highWater(), doc), "the high-water mark is the first document's")
                    verify(signer.apps().isEmpty(), "no enrolled apps")
                    verify(signer.certificates().isEmpty(), "no enrolled certificates")

                    val limited = signer.setRecordMaxAge(86_400uL)
                    verify(limited.version == 2uL && limited.recordMaxAge == 86_400uL, "record age set")
                    verify(!limited.hash.contentEquals(doc.hash) && !limited.bodyHash.contentEquals(doc.bodyHash),
                        "a new version has new hashes")
                    verify(statusSameDoc(signer.identityDoc(), limited), "record age read back")
                    verify(statusMarks(signer.highWater(), limited), "the high-water mark follows the new version")
                    try {
                        signer.setRecordMaxAge(0uL)
                        error("zero record age accepted")
                    } catch (failure: SignerFfiException.InvalidData) {
                        verify(failure.kind == CoreFailure.INVALID, "zero record age refused as invalid data")
                    }
                    verify(statusSameDoc(signer.identityDoc(), limited), "same document after zero record age")

                    // The two flags differ, so a swap of them shows.
                    val settings = ConnectRequestsView(enabled = true, maxPending = 17uL, push = false)
                    val configured = signer.setConnectRequests(settings)
                    verify(configured.version == 3uL && configured.connectRequests.enabled &&
                        !configured.connectRequests.push && configured.connectRequests.maxPending == 17uL &&
                        configured.recordMaxAge == 86_400uL, "connect request settings set")
                    verify(statusSameDoc(signer.identityDoc(), configured), "connect request settings read back")

                    val cleared = signer.setRecordMaxAge(null)
                    verify(cleared.version == 4uL && cleared.recordMaxAge == null &&
                        cleared.connectRequests == settings, "record age cleared")
                    verify(statusSameDoc(signer.identityDoc(), cleared), "cleared record age read back")

                    // A known app: the lists show it, with its certificate.
                    val appId = signer.fixtureApproveSampleApp()
                    val apps = signer.apps()
                    verify(apps.size == 1 && apps[0].appId.contentEquals(appId) &&
                        apps[0].standing == AppStandingView.Listed, "the approved app is listed")
                    val cert = checkNotNull(apps[0].cert) { "the listed app's certificate" }
                    verify(cert.appId.contentEquals(appId) && apps[0].listedCert?.contentEquals(cert.hash) == true &&
                        cert.scopes == listOf("sample-a:private-label"), "the listed app's certificate")
                    val certs = signer.certificates()
                    verify(certs.size == 1 && certs[0].hash.contentEquals(cert.hash), "the signer keeps its certificate")
                    signerEnd(signer)
                }
            }
        }
        require(completed == 21, "every status check ran")
    } finally {
        root.toFile().deleteRecursively()
    }
}
