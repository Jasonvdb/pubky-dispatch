// The Kotlin host's checks of renewing an app's certificate.
package pubky.dispatch.signer.tests

import java.nio.file.Files
import pubky.dispatch.signer.*

/** Check the renewal of an app's certificate (Dispatch spec 3.2). */
suspend fun checkRenewal() {
    var completed = 0
    fun verify(condition: Boolean, what: String) {
        require(condition, what)
        completed += 1
    }

    registerSampleProtocol()
    val root = Files.createTempDirectory("signer-renewal")
    try {
        val vault = MemoryVault().also { it.import() }
        step("renewal: renew, reduce and renew the expiring") {
            FixtureApps(seed(), MemoryHomeserver()).use { fixture ->
                fixture.signerWithApps(vault, FileStore(root), "https://dispatch.example", 2u).use { signer ->
                    suspend fun app(id: ByteArray) = signer.apps().single { it.appId.contentEquals(id) }
                    val ids = fixture.appIds()
                    verify(ids.size == 2 && ids.all { it.size == 16 } && !ids.first().contentEquals(ids.last()),
                        "two distinct app IDs")
                    val (first, second) = ids
                    val scopes = listOf("sample-a", "sample-b")
                    val old = checkNotNull(app(first).cert)
                    verify(old.scopes == scopes && app(second).cert?.scopes == scopes, "both apps have both scopes")

                    val before = checkNotNull(signer.identityDoc())
                    val day = 86_400_000uL
                    val later = old.expiresAt + day
                    val renewed = signer.renew(first, CertChangeView(scopes = null, expiresAt = later))
                    val published = checkNotNull(signer.identityDoc())
                    verify(renewed.version == before.version + 1uL && published.version == renewed.version &&
                        published.hash.contentEquals(renewed.hash), "the returned version is the newest version")
                    val open = app(first)
                    val cert = checkNotNull(open.cert)
                    verify(!cert.hash.contentEquals(old.hash) && open.listedCert.contentEquals(cert.hash) &&
                        cert.expiresAt == later && cert.scopes == old.scopes, "new listed certificate with the requested expiry")
                    verify(open.renewalOpen, "expiry extension is open")
                    verify(signer.completeRenewals().isEmpty(), "no closure before take-up")
                    verify(app(first).renewalOpen, "renewal is still open after the check")
                    fixture.takeUpRenewal(first)
                    verify(signer.completeRenewals().single().contentEquals(first), "only the app that took up its renewal closed")
                    verify(!app(first).renewalOpen, "the app's renewal is closed")

                    val kept = listOf("sample-a")
                    val terms = scopeTerms(kept)
                    verify(terms.keyed == kept && terms.permissions == listOf("claims.read"), "terms of the kept scope")
                    val previous = checkNotNull(signer.identityDoc())
                    val change = CertChangeView(scopes = kept, expiresAt = null)
                    verify(change.toString() == "CertChangeView(<redacted>)", "the change's description hides its scopes")
                    val reduction = signer.renew(second, change)
                    verify(reduction.version == previous.version + 1uL && signer.identityDoc()?.version == reduction.version + 1uL,
                        "the reduction returns the renewing version and delivers its closing version")
                    val reduced = app(second)
                    val reducedCert = checkNotNull(reduced.cert)
                    verify(reducedCert.scopes == kept && reducedCert.permissions == terms.permissions && !reduced.renewalOpen,
                        "the other app keeps only the requested scope and its permissions")
                    try {
                        signer.renew(ByteArray(16), CertChangeView(scopes = null, expiresAt = null))
                        error("unknown app was renewed")
                    } catch (failure: SignerFfiException.Refused) {
                        verify(failure.kind == RefusalKind.NOT_LISTED, "unknown app has the not-listed refusal")
                    }

                    verify(signer.renewExpiring().isEmpty(), "neither certificate is due yet")
                    fixture.advanceTimeMs((later - old.issuedAt) / 2uL + day)
                    val automatic = signer.renewExpiring()
                    verify(automatic.size == ids.size && ids.all { id -> automatic.any { it.contentEquals(id) } },
                        "both apps past half their certificate lifetime were renewed")
                    verify(signer.renewExpiring().isEmpty(), "the next call renews neither app again")
                    signerEnd(signer)
                }
            }
        }
        require(completed == 17, "every renewal check ran")
    } finally {
        root.toFile().deleteRecursively()
    }
}
