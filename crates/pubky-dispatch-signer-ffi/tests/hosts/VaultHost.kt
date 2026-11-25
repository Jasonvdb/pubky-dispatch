// The Kotlin host's checks of the keyring over a host vault.
package pubky.dispatch.signer.tests

import com.sun.jna.Native
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.runBlocking
import pubky.dispatch.signer.HostVault
import pubky.dispatch.signer.KeyFailure
import pubky.dispatch.signer.SignerFfiException
import pubky.dispatch.signer.VaultAddOutcome
import pubky.dispatch.signer.VaultFailure
import pubky.dispatch.signer.createKeyring
import pubky.dispatch.signer.fixtureVaultDelete
import pubky.dispatch.signer.openKeyring

// A vault in memory, holding a test seed. A real vault keeps the seed in the platform's
// secure storage. `failing` names the one method that throws `failure`.
class MemoryVault(
    private val failing: String? = null,
    private val failure: Throwable? = null,
) : HostVault {
    private var held: ByteArray? = null

    // The methods the bindings called, in order.
    val calls = CopyOnWriteArrayList<String>()

    // Set by a check: how many bytes a load hands over, and what a load does first.
    var loadLength = 32
    var duringLoad: (() -> Unit)? = null

    private fun failIn(method: String) {
        calls.add(method)
        if (failing == method && failure != null) throw failure
    }

    @Synchronized override fun load(): ByteArray? {
        failIn("load")
        duringLoad?.invoke()
        return held?.copyOf(loadLength)
    }

    @Synchronized override fun add(secret: ByteArray): VaultAddOutcome {
        failIn("add")
        if (held != null) return VaultAddOutcome.OCCUPIED
        held = secret.copyOf()
        return VaultAddOutcome.STORED
    }

    @Synchronized override fun delete(expected: ByteArray) {
        failIn("delete")
        if (held?.contentEquals(expected) == true) {
            held?.fill(0)
            held = null
        }
    }

    // What the vault holds, read past the method that fails.
    @Synchronized fun holds(): ByteArray? = held?.copyOf()

    // Put the vector seed in, as an import does, past the method that fails.
    @Synchronized fun import() {
        held = seed()
    }

    // Another identity's seed takes the place of the held one.
    @Synchronized fun replace(seed: ByteArray) {
        held = seed.copyOf()
    }

    override fun toString() = "MemoryVault(..)"
}

private suspend fun checkKeyFailure(kind: KeyFailure, call: suspend () -> Unit) {
    try {
        call()
        require(false, "expected a key failure")
    } catch (failure: SignerFfiException.Key) {
        require(failure.kind == kind, "the key failure's kind")
        for (text in listOf(failure.toString(), failure.message.orEmpty())) {
            require(!showsSeed(text), "the seed in the key failure")
            require(!text.contains(FIXTURE_TEXT) && !text.contains("VaultFailure"), "the host's diagnostic")
        }
    }
}

/** Check the identity keyring over a host vault (Dispatch spec 13.3). */
suspend fun checkVault() {
    val vault = MemoryVault()
    createKeyring(vault).use { created ->
        val held = vault.holds() ?: throw IllegalStateException("the vault is empty after creation")
        require(held.size == 32, "the stored seed's length")
        val publicKey = created.publicKey()
        require(publicKey.size == 32 && !publicKey.contentEquals(held), "the identity's public key")
        require(created.pubkyId().isNotEmpty(), "the identity's Pubky ID")
        openKeyring(vault).use { opened ->
            require(opened.pubkyId() == created.pubkyId(), "the reopened identity")
        }
        checkKeyFailure(KeyFailure.OCCUPIED) { createKeyring(vault).close() }
        require(vault.holds().contentEquals(held), "the occupied vault kept its seed")
        // The bindings' own deletion: compare, then delete.
        fixtureVaultDelete(vault, seed())
        require(vault.holds().contentEquals(held), "deleting another seed kept the identity")
        fixtureVaultDelete(vault, held)
        fixtureVaultDelete(vault, held)
        require(vault.holds() == null, "deleting the held seed emptied the vault")
        checkKeyFailure(KeyFailure.MISSING) { created.backupPublicKey() }
    }
    checkKeyFailure(KeyFailure.MISSING) { openKeyring(vault).close() }

    // Whatever a vault method throws, a typed failure, an exception or an error, is the
    // vault's failure: never a success, and nothing the vault held changes.
    val failures = listOf<() -> Throwable>(
        { VaultFailure.Locked() },
        { VaultFailure.Unavailable() },
        { VaultFailure.Other() },
        { IllegalStateException(FIXTURE_TEXT) },
        { AssertionError(FIXTURE_TEXT) },
    )
    // An error is thrown on to JNA's handler once the vault's failure is reported: counted
    // here, where the default handler would print it.
    var thrownOn = 0
    val handler = Native.getCallbackExceptionHandler()
    Native.setCallbackExceptionHandler { _, _ -> thrownOn += 1 }
    for (failure in failures) {
        // Each failed call is made once, and nothing follows it: no retry, no clean-up.
        val loading = MemoryVault("load", failure())
        loading.import()
        checkKeyFailure(KeyFailure.VAULT) { openKeyring(loading).close() }
        require(loading.calls == listOf("load"), "the vault's calls around a failed load")

        val adding = MemoryVault("add", failure())
        checkKeyFailure(KeyFailure.VAULT) { createKeyring(adding).close() }
        require(adding.calls == listOf("add"), "the vault's calls around a failed add")

        val deleting = MemoryVault("delete", failure())
        deleting.import()
        checkKeyFailure(KeyFailure.VAULT) { fixtureVaultDelete(deleting, seed()) }
        require(deleting.calls == listOf("delete"), "the vault's calls around a failed delete")
    }
    Native.setCallbackExceptionHandler(handler)
    require(thrownOn == 3, "the vault's errors, reported to the host")

    val imported = MemoryVault()
    imported.import()
    checkKeyFailure(KeyFailure.OCCUPIED) { createKeyring(imported).close() }
    openKeyring(imported).use { opened ->
        require(opened.pubkyId() == PUBKY_ID, "the imported identity's Pubky ID")
        val backup = opened.backupPublicKey()
        require(backup.publicKey.size == 32 && backup.keyId.size == 8, "the backup key's lengths")
        // A keyring stays bound to the identity it opened.
        imported.replace(ByteArray(32) { 5 })
        checkKeyFailure(KeyFailure.MISMATCH) { opened.backupPublicKey() }
        require(opened.pubkyId() == PUBKY_ID, "the keyring's identity once the vault holds another")
    }

    // A load of another length is the vault's failure.
    for (length in listOf(31, 33)) {
        val odd = MemoryVault()
        odd.import()
        odd.loadLength = length
        checkKeyFailure(KeyFailure.VAULT) { openKeyring(odd).close() }
    }

    // A call a vault method starts on its own thread, and waits for, is refused; the call
    // the method serves goes on.
    val calling = MemoryVault()
    calling.import()
    var inner: Throwable? = null
    calling.duringLoad = {
        inner = runCatching { runBlocking { openKeyring(MemoryVault()).close() } }.exceptionOrNull()
    }
    openKeyring(calling).close()
    require(inner is SignerFfiException.InvalidInput, "a call from inside a vault callback")
}
