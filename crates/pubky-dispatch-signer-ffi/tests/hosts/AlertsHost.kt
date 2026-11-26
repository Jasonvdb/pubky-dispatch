// The Kotlin host's checks of the signer's alerts.
package pubky.dispatch.signer.tests

import java.nio.file.Files
import pubky.dispatch.signer.*

/** Check the signer's alerts (Dispatch spec 4.3). */
suspend fun checkAlerts() {
    var completed = 0
    fun verify(condition: Boolean, what: String) {
        require(condition, what)
        completed += 1
    }

    fun onlyRollback(alerts: List<SeenAlert>): SeenAlert {
        verify(alerts.size == 1, "one uncleared alert")
        val alert = alerts.single()
        val facts = alert.facts() as? AlertFacts.Rollback ?: error("expected a rollback")
        verify(facts.source == AlertSource.SERVICE, "rollback at the service")
        verify(facts.version == null, "missing copy has no version")
        verify(facts.generation == null, "missing copy has no generation")
        verify(facts.highWaterVersion == 1uL, "enrollment is the high-water version")
        return alert
    }

    registerSampleProtocol()
    val root = Files.createTempDirectory("signer-alerts")
    try {
        val vault = MemoryVault().also { it.import() }
        step("alerts: a lost copy") {
            FixtureService(seed(), MemoryHomeserver()).use { service ->
                service.createSigner(vault, FileStore(root), "https://dispatch.example").use { signer ->
                    signer.resume()
                    verify(signer.status() == SignerStatus.Signing, "signer enrolled")
                    verify(signer.alerts().isEmpty(), "enrollment left no alerts")
                    service.loseIdentity()
                    val setting = try {
                        signer.setRecordMaxAge(3_600uL)
                        true
                    } catch (failure: SignerFfiException.Alarm) {
                        failure.alert == AlertKind.ROLLBACK
                    }
                    verify(setting, "setting completed or raised the rollback")

                    onlyRollback(signer.alerts()).use { alert ->
                        verify(!alert.namesApp(ByteArray(16)), "identity rollback names no app")
                        val invalid = try {
                            alert.namesApp(ByteArray(15))
                            false
                        } catch (_: SignerFfiException.InvalidInput) {
                            true
                        }
                        verify(invalid, "short app ID is invalid input")

                        val alarm = try {
                            alert.clear()
                            false
                        } catch (failure: SignerFfiException.Alarm) {
                            failure.alert == AlertKind.ROLLBACK
                        }
                        verify(alarm, "clearing the lost copy raised the rollback again")
                    }
                    onlyRollback(signer.alerts()).use { kept ->
                        verify(signer.status() == SignerStatus.Alarm, "signer still stands at alarm")
                        signerEnd(signer)
                        // An alert kept past its signer's end still reads, and clears nothing.
                        verify(kept.facts() is AlertFacts.Rollback, "a kept alert still reads")
                        val closed = try {
                            kept.clear()
                            false
                        } catch (failure: SignerFfiException.InvalidInput) {
                            failure.reason == "the signer is closed"
                        }
                        verify(closed, "a kept alert's clear is refused as closed")
                    }
                }
            }
        }
        // A handle clears its own occurrence only: the same alert raised again later is
        // another occurrence, which the user hasn't seen.
        val occurrences = Files.createTempDirectory("signer-occurrences")
        try {
            step("alerts: occurrences") {
                val home = MemoryHomeserver()
                FixtureService(seed(), home).use { service ->
                    service.createSigner(vault, FileStore(occurrences), "https://dispatch.example").use { signer ->
                        signer.resume()
                        suspend fun loseBackup() {
                            home.delete(SIGNER_BACKUP_PATH)
                            signer.setRecordMaxAge(86_400uL)
                        }
                        loseBackup()
                        val first = signer.alerts().single()
                        val again = signer.alerts().single()
                        verify(first.facts() is AlertFacts.BackupMissing && again.facts() is AlertFacts.BackupMissing,
                            "the missing backup, listed twice")
                        first.clear()
                        verify(signer.alerts().isEmpty(), "its clear clears it")
                        loseBackup()
                        val later = signer.alerts().single()
                        first.clear()
                        again.clear()
                        verify(signer.alerts().singleOrNull()?.facts() is AlertFacts.BackupMissing,
                            "neither handle of the first occurrence clears the later one")
                        later.clear()
                        verify(signer.alerts().isEmpty(), "the later occurrence clears through its own handle")
                        signerEnd(signer)
                    }
                }
            }
        } finally {
            occurrences.toFile().deleteRecursively()
        }
        require(completed == 23, "every alert check ran")
    } finally {
        root.toFile().deleteRecursively()
    }
}

/** Where the signer keeps its backup on the Homeserver (Dispatch wire 3.13). */
private const val SIGNER_BACKUP_PATH = "/priv/pubky-dispatch/v1/signer-backup.json"
