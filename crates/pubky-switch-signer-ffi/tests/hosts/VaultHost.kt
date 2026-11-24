// The Kotlin host's checks of the keyring over a host vault.
package pubky.switch.signer.tests

import pubky.switch.signer.HostVault
import pubky.switch.signer.KeyFailure
import pubky.switch.signer.SignerFfiException
import pubky.switch.signer.VaultAdd
import pubky.switch.signer.VaultFailure
import pubky.switch.signer.createKeyring
import pubky.switch.signer.openKeyring

private class MemoryVault(private val loadFailure: Exception? = null) : HostVault {
    private var held: ByteArray? = null

    @Synchronized override fun load(): ByteArray? {
        if (loadFailure != null) throw loadFailure
        return held?.copyOf()
    }

    @Synchronized override fun add(secret: ByteArray): VaultAdd {
        if (held != null) return VaultAdd.OCCUPIED
        held = secret.copyOf()
        return VaultAdd.STORED
    }

    @Synchronized override fun delete(expected: ByteArray) {
        if (held?.contentEquals(expected) == true) {
            held?.fill(0)
            held = null
        }
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
        val held = vault.load() ?: throw IllegalStateException("the vault is empty after creation")
        require(held.size == 32, "the stored seed's length")
        val publicKey = created.publicKey()
        require(publicKey.size == 32 && !publicKey.contentEquals(held), "the identity's public key")
        require(created.pubkyId().isNotEmpty(), "the identity's Pubky ID")
        openKeyring(vault).use { opened ->
            require(opened.pubkyId() == created.pubkyId(), "the reopened identity")
        }
        checkKeyFailure(KeyFailure.OCCUPIED) { createKeyring(vault).close() }
        require(vault.load().contentEquals(held), "the occupied vault kept its seed")
        vault.delete(seed())
        require(vault.load().contentEquals(held), "deleting another seed kept the identity")
        vault.delete(held)
        vault.delete(held)
        require(vault.load() == null, "deleting the held seed emptied the vault")
        checkKeyFailure(KeyFailure.MISSING) { created.backupPublic() }
    }
    checkKeyFailure(KeyFailure.MISSING) { openKeyring(vault).close() }

    val failures = listOf(
        VaultFailure.Locked(),
        VaultFailure.Unavailable(),
        VaultFailure.Other(),
        IllegalStateException(FIXTURE_TEXT),
    )
    for (failure in failures) {
        val failing = MemoryVault(failure)
        require(failing.add(seed()) == VaultAdd.STORED, "the failing vault holds the vector seed")
        checkKeyFailure(KeyFailure.VAULT) { openKeyring(failing).close() }
    }

    val imported = MemoryVault()
    require(imported.add(seed()) == VaultAdd.STORED, "the imported seed was stored")
    require(imported.add(seed()) == VaultAdd.OCCUPIED, "adding the same seed found the vault occupied")
    openKeyring(imported).use { opened ->
        require(opened.pubkyId() == PUBKY_ID, "the imported identity's Pubky ID")
        val backup = opened.backupPublic()
        require(backup.publicKey.size == 32 && backup.kid.size == 8, "the backup public key and kid lengths")
    }
}
