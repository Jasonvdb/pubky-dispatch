// The Swift host's checks of the keyring over a host vault.
import Foundation
import PubkySwitchSigner

private final class MemoryVault: HostVault, @unchecked Sendable, CustomDebugStringConvertible {
    private let lock = NSLock()
    private var held: Data?
    private let loadFailure: (any Error)?

    init(loadFailure: (any Error)? = nil) {
        self.loadFailure = loadFailure
    }

    func load() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if let loadFailure { throw loadFailure }
        return held
    }

    func add(secret: Data) -> VaultAdd {
        lock.lock()
        defer { lock.unlock() }
        guard held == nil else { return .occupied }
        held = secret
        return .stored
    }

    func delete(expected: Data) {
        lock.lock()
        defer { lock.unlock() }
        if held == expected { held = nil }
    }

    var debugDescription: String { "MemoryVault(..)" }
}

private func checkKeyFailure(_ expected: KeyFailure, _ call: () async throws -> Void) async {
    do {
        try await call()
        check(false, "expected a key failure")
    } catch let failure as SignerFfiError {
        guard case .Key(let kind) = failure else {
            check(false, "expected the key failure's kind")
            return
        }
        check(kind == expected, "the key failure's kind")
        let hex = String(seedHex.prefix(16))
        let bytes = seed().prefix(4).map(String.init).joined(separator: ", ")
        for text in [String(describing: failure), String(reflecting: failure), failure.localizedDescription] {
            check(!text.contains(hex) && !text.contains(bytes), "the seed in the key failure")
            check(!text.contains(fixtureText) && !text.contains("VaultFailure"), "the host's diagnostic")
        }
    } catch {
        check(false, "an untyped key failure")
    }
}

/// Check the identity keyring over a host vault (Switch spec 13.3).
func checkVault() async {
    do {
        let vault = MemoryVault()
        let created = try await createKeyring(vault: vault)
        guard let held = try vault.load() else {
            check(false, "the vault is empty after creation")
            return
        }
        check(held.count == 32, "the stored seed's length")
        let publicKey = created.publicKey()
        check(publicKey.count == 32 && publicKey != held, "the identity's public key")
        check(!created.pubkyId().isEmpty, "the identity's Pubky ID")
        let opened = try await openKeyring(vault: vault)
        check(opened.pubkyId() == created.pubkyId(), "the reopened identity")
        await checkKeyFailure(.occupied) { _ = try await createKeyring(vault: vault) }
        check(try vault.load() == held, "the occupied vault kept its seed")
        vault.delete(expected: seed())
        check(try vault.load() == held, "deleting another seed kept the identity")
        vault.delete(expected: held)
        vault.delete(expected: held)
        check(try vault.load() == nil, "deleting the held seed emptied the vault")
        await checkKeyFailure(.missing) { _ = try await created.backupPublic() }
        await checkKeyFailure(.missing) { _ = try await openKeyring(vault: vault) }

        let failures: [any Error] = [
            VaultFailure.Locked, VaultFailure.Unavailable, VaultFailure.Other,
            NSError(domain: fixtureText, code: 1, userInfo: [NSLocalizedDescriptionKey: fixtureText]),
        ]
        for failure in failures {
            let failing = MemoryVault(loadFailure: failure)
            check(failing.add(secret: seed()) == .stored, "the failing vault holds the vector seed")
            await checkKeyFailure(.vault) { _ = try await openKeyring(vault: failing) }
        }

        let imported = MemoryVault()
        check(imported.add(secret: seed()) == .stored, "the imported seed was stored")
        check(imported.add(secret: seed()) == .occupied, "adding the same seed found the vault occupied")
        let identity = try await openKeyring(vault: imported)
        check(identity.pubkyId() == pubkyId, "the imported identity's Pubky ID")
        let backup = try await identity.backupPublic()
        check(backup.publicKey.count == 32 && backup.kid.count == 8, "the backup public key and kid lengths")
    } catch {
        check(false, "the vault refused a valid call")
    }
}
