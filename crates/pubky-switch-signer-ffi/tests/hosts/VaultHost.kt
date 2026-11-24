// The Kotlin host's checks of the keyring over a host vault.
package pubky.switch.signer.tests

import pubky.switch.signer.HostVault
import pubky.switch.signer.KeyFailure
import pubky.switch.signer.SignerFfiException
import pubky.switch.signer.VaultAdd
import pubky.switch.signer.VaultFailure
import pubky.switch.signer.createKeyring
import pubky.switch.signer.fixtureVaultDelete
import pubky.switch.signer.openKeyring

// A vault in memory, holding a test seed. A real vault keeps the seed in the platform's
// secure storage. `failing` names the one method that throws `failure`.
private class MemoryVault(
    private val failing: String? = null,
    private val failure: Throwable? = null,
) : HostVault {
    private var held: ByteArray? = null

    private fun failIn(method: String) {
        if (failing == method && failure != null) throw failure
    }

    @Synchronized override fun load(): ByteArray? {
        failIn("load")
        return held?.copyOf()
    }

    @Synchronized override fun add(secret: ByteArray): VaultAdd {
        failIn("add")
        if (held != null) return VaultAdd.OCCUPIED
        held = secret.copyOf()
        return VaultAdd.STORED
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

/** Check the identity keyring over a host vault (Switch spec 13.3). */
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
    for (failure in failures) {
        val loading = MemoryVault("load", failure())
        loading.import()
        checkKeyFailure(KeyFailure.VAULT) { openKeyring(loading).close() }

        val adding = MemoryVault("add", failure())
        checkKeyFailure(KeyFailure.VAULT) { createKeyring(adding).close() }
        require(adding.holds() == null, "a failed add stored nothing")

        val deleting = MemoryVault("delete", failure())
        deleting.import()
        checkKeyFailure(KeyFailure.VAULT) { fixtureVaultDelete(deleting, seed()) }
        require(deleting.holds().contentEquals(seed()), "a failed delete kept the seed")
    }

    val imported = MemoryVault()
    require(imported.add(seed()) == VaultAdd.STORED, "the imported seed was stored")
    require(imported.add(seed()) == VaultAdd.OCCUPIED, "adding the same seed found the vault occupied")
    openKeyring(imported).use { opened ->
        require(opened.pubkyId() == PUBKY_ID, "the imported identity's Pubky ID")
        val backup = opened.backupPublicKey()
        require(backup.publicKey.size == 32 && backup.keyId.size == 8, "the backup key's lengths")
    }
}
