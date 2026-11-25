// The Kotlin host's checks of the signer's views and settings.
package pubky.dispatch.signer.tests

import java.nio.file.Files
import pubky.dispatch.signer.*

private fun statusSameDoc(read: IdentityDocView?, expected: IdentityDocView): Boolean =
    read != null && read.generation == expected.generation && read.version == expected.version &&
        read.hash.contentEquals(expected.hash) && read.bodyHash.contentEquals(expected.bodyHash) &&
        read.recordMaxAge == expected.recordMaxAge && read.connectRequests == expected.connectRequests

/** Check the newest version and the signer's settings (Dispatch spec 4.3). */
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
                    val mark = checkNotNull(signer.highWater()) { "missing enrolled high-water mark" }
                    verify(doc.generation == 1uL && doc.version == 1uL, "first document")
                    verify(doc.recordMaxAge == null &&
                        doc.connectRequests == ConnectRequestsView(enabled = false, maxPending = 50uL, push = false),
                        "first document settings")
                    verify(mark.generation == 1uL && mark.version == 1uL, "first high-water mark")
                    verify(doc.hash.size == 32 && mark.docHash.contentEquals(doc.hash), "high-water document hash")
                    verify(doc.bodyHash.size == 32 && mark.bodyHash.contentEquals(doc.bodyHash), "high-water body hash")
                    verify(signer.apps().isEmpty(), "no enrolled apps")
                    verify(signer.certificates().isEmpty(), "no enrolled certificates")

                    val limited = signer.setRecordMaxAge(86_400uL)
                    verify(limited.version == 2uL && limited.recordMaxAge == 86_400uL, "record age set")
                    verify(statusSameDoc(signer.identityDoc(), limited), "record age read back")
                    try {
                        signer.setRecordMaxAge(0uL)
                        error("zero record age accepted")
                    } catch (failure: SignerFfiException.InvalidData) {
                        verify(failure.kind == CoreFailure.INVALID, "zero record age refused as invalid data")
                    }
                    verify(statusSameDoc(signer.identityDoc(), limited), "same document after zero record age")

                    val settings = ConnectRequestsView(enabled = true, maxPending = 17uL, push = true)
                    val configured = signer.setConnectRequests(settings)
                    verify(configured.version == 3uL && configured.connectRequests == settings &&
                        configured.recordMaxAge == 86_400uL, "connect request settings set")
                    verify(statusSameDoc(signer.identityDoc(), configured), "connect request settings read back")

                    val cleared = signer.setRecordMaxAge(null)
                    verify(cleared.version == 4uL && cleared.recordMaxAge == null &&
                        cleared.connectRequests == settings, "record age cleared")
                    verify(statusSameDoc(signer.identityDoc(), cleared), "cleared record age read back")
                    signerEnd(signer)
                }
            }
        }
        require(completed == 17, "every status check ran")
    } finally {
        root.toFile().deleteRecursively()
    }
}
