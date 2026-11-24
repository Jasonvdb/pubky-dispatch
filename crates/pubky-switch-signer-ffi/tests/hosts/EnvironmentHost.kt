// Host checks for the signer environment and protocol authority (Switch spec 3.2).
package pubky.switch.signer.tests

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import pubky.switch.signer.*

private class MemoryHomeserver(private val denied: Boolean = false) : HostHomeserver {
    private val files = ConcurrentHashMap<String, ByteArray>()
    val calls = CopyOnWriteArrayList<String>()
    @Volatile var written: ByteArray? = null
        private set

    override suspend fun get(path: String): ByteArray? {
        calls.add("get $path")
        if (denied) throw HomeserverFailure.Denied()
        return files[path]?.copyOf()
    }

    override suspend fun put(path: String, bytes: ByteArray) {
        calls.add("put $path")
        files[path] = bytes.copyOf()
        written = bytes.copyOf()
    }

    override suspend fun delete(path: String) {
        calls.add("delete $path")
        files.remove(path)
    }
}

private inline fun signerFailure(call: () -> Unit): SignerFfiException {
    try {
        call()
    } catch (failure: SignerFfiException) {
        return failure
    }
    throw IllegalStateException("expected a signer failure")
}

private fun checkSampleFailure(sample: SampleFailure) {
    val failure = signerFailure { sampleFailure(sample) }
    val matches = when (sample) {
        SampleFailure.CLOCK_OFF -> failure is SignerFfiException.Refused &&
            failure.kind == RefusalKind.CLOCK_OFF &&
            failure.measurements == RefusalMeasurements.ClockOff(5uL, 9uL)
        SampleFailure.HANDING_OVER -> failure is SignerFfiException.Refused &&
            failure.kind == RefusalKind.HANDING_OVER &&
            failure.toApp?.contentEquals(ByteArray(16) { 3 }) == true
        SampleFailure.KEY_RECOVERY -> failure is SignerFfiException.Refused &&
            failure.kind == RefusalKind.KEY_RECOVERY &&
            failure.stop == KeyRecoveryStopKind.SERVICE_BEHIND &&
            failure.measurements == RefusalMeasurements.ServiceBehind(2uL, 4uL)
        SampleFailure.STORE_TOO_LARGE -> failure is SignerFfiException.Store &&
            failure.kind == StoreErrorKind.TOO_LARGE && failure.size == 13uL && failure.cap == 12uL
        SampleFailure.TRANSPORT_TOO_LARGE -> failure is SignerFfiException.Service &&
            failure.kind == ServiceFailure.TRANSPORT && failure.transport == TransportFailure.TOO_LARGE &&
            failure.limit == 64uL && !failure.authenticated && failure.status == null && failure.code == null
        SampleFailure.ERROR_ANSWER -> failure is SignerFfiException.Service &&
            failure.kind == ServiceFailure.ERROR_ANSWER && failure.authenticated && failure.status == 429.toUShort() &&
            failure.code == "rate_limited" && failure.retryAfterS == 37uL &&
            failure.retry == RetryKind.AFTER_RETRY_AFTER && !failure.notHosted && failure.transport == null
        SampleFailure.BODY_UNREAD -> failure is SignerFfiException.Service &&
            failure.kind == ServiceFailure.BODY_UNREAD && failure.authenticated && failure.status == 429.toUShort() &&
            failure.code == "rate_limited" && failure.retryAfterS == 19uL && failure.retry == null && !failure.notHosted
        SampleFailure.UNSIGNED_STATUS -> failure is SignerFfiException.Service &&
            failure.kind == ServiceFailure.BAD_SERVICE_SIGNATURE && !failure.authenticated &&
            failure.status == 404.toUShort() && failure.code == null && failure.retryAfterS == null && !failure.notHosted
        SampleFailure.UNDECODABLE -> failure is SignerFfiException.Records &&
            failure.kind == RecordsFailure.UNDECODABLE && failure.record == RecordKind.FLOW &&
            failure.line == 7uL && failure.column == 11uL && failure.write == null
        SampleFailure.NOT_NAMED -> failure is SignerFfiException.NotNamed &&
            failure.install.contentEquals(ByteArray(16) { 5 })
        SampleFailure.HANDED_OVER -> failure is SignerFfiException.HandedOver &&
            failure.install.contentEquals(ByteArray(16) { 7 })
        SampleFailure.INVALID_DATA -> failure is SignerFfiException.InvalidData && failure.kind == CoreFailure.INVALID
        SampleFailure.STORED_DATA -> failure is SignerFfiException.StoredData && failure.kind == CoreFailure.INVALID
        SampleFailure.ALARM -> failure is SignerFfiException.Alarm && failure.alert == AlertKind.BACKUP_UNREADABLE
    }
    require(matches, "wrong typed fields for $sample")
    require(!failure.toString().contains(FIXTURE_TEXT) && !failure.message.orEmpty().contains(FIXTURE_TEXT),
        "inner error text crossed the binding")
}

/** Check the environment, scope terms and signer errors (Switch spec 3.2). */
suspend fun checkEnvironment() {
    registerSampleProtocol()
    registerSampleProtocol()
    require(protocolNames() == listOf("sample"), "registered protocol names")
    val terms = scopeTerms(listOf("sample-a"))
    require(terms.keyed == listOf("sample-a") && terms.permissions == listOf("claims.read"), "sample authority")
    for ((scope, kind) in listOf("sample-b" to RefusalKind.PROTOCOL_RULE, "unknown" to RefusalKind.UNKNOWN_SCOPES)) {
        val failure = signerFailure { scopeTerms(listOf(scope)) }
        require(failure is SignerFfiException.Refused && failure.kind == kind, "scope refusal")
        val named = if (kind == RefusalKind.UNKNOWN_SCOPES) listOf(scope) else null
        require((failure as SignerFfiException.Refused).scopes == named, "refused scopes")
    }
    SampleFailure.entries.forEach(::checkSampleFailure)

    val home = MemoryHomeserver()
    SignerEnvironment(home, TransportOptions()).close()
    val invalid = signerFailure { SignerEnvironment(home, TransportOptions(requestTimeoutMs = 0uL)).close() }
    require(invalid is SignerFfiException.InvalidInput && invalid.reason == "request_timeout_ms", "zero timeout")

    val path = "/sample"
    val bytes = byteArrayOf(0, -1, 3)
    val trip = homeserverRoundTrip(home, path, bytes)
    require(trip.absentBefore && trip.matchedAfterPut && trip.absentAfter, "homeserver round trip")
    require(home.written?.contentEquals(bytes) == true, "host received the supplied bytes")
    require(home.calls == listOf("get", "put", "get", "delete", "delete", "get").map { "$it $path" }, "homeserver calls")
    val denied = MemoryHomeserver(denied = true)
    val failure = signerFailure { homeserverRoundTrip(denied, path, bytes) }
    require(failure is SignerFfiException.Homeserver && failure.kind == TransportFailure.REFUSED &&
        failure.size == null && failure.status == null, "denied read")
    require(denied.calls == listOf("get $path"), "denial stopped the round trip")
}
