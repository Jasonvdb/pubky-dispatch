// The Swift host's checks of the keyring over a host vault.
import Foundation
import PubkyDispatchSigner

// A vault in memory, holding a test seed. A real vault keeps the seed in the platform's
// secure storage. `failing` names the one method that throws `failure`.
private final class MemoryVault: HostVault, @unchecked Sendable, CustomDebugStringConvertible {
    private let lock = NSLock()
    private var held: Data?
    private var called: [String] = []
    private var loadLength = 32
    private let failing: String?
    private let failure: (any Error)?

    init(failing: String? = nil, failure: (any Error)? = nil) {
        self.failing = failing
        self.failure = failure
    }

    private func failIn(_ method: String) throws {
        called.append(method)
        if failing == method, let failure { throw failure }
    }

    func load() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        try failIn("load")
        guard let held else { return nil }
        return held.prefix(loadLength) + Data(count: max(0, loadLength - held.count))
    }

    func add(secret: Data) throws -> VaultAddOutcome {
        lock.lock()
        defer { lock.unlock() }
        try failIn("add")
        guard held == nil else { return .occupied }
        held = secret
        return .stored
    }

    func delete(expected: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try failIn("delete")
        if held == expected {
            held?.resetBytes(in: 0..<expected.count)
            held = nil
        }
    }

    // What the vault holds, read past the method that fails.
    func holds() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return held
    }

    // Put the vector seed in, as an import does, past the method that fails.
    func importSeed() {
        lock.lock()
        defer { lock.unlock() }
        held = seed()
    }

    // Another identity's seed takes the place of the held one.
    func replace(_ seed: Data) {
        lock.lock()
        defer { lock.unlock() }
        held = seed
    }

    // How many bytes a load hands over from now on.
    func loads(_ length: Int) {
        lock.lock()
        defer { lock.unlock() }
        loadLength = length
    }

    // The methods the bindings called, in order.
    func calls() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return called
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

/// Check the identity keyring over a host vault (Dispatch spec 13.3).
func checkVault() async {
    do {
        let vault = MemoryVault()
        let created = try await createKeyring(vault: vault)
        guard let held = vault.holds() else {
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
        check(vault.holds() == held, "the occupied vault kept its seed")
        // The bindings' own deletion: compare, then delete.
        try await fixtureVaultDelete(vault: vault, expected: seed())
        check(vault.holds() == held, "deleting another seed kept the identity")
        try await fixtureVaultDelete(vault: vault, expected: held)
        try await fixtureVaultDelete(vault: vault, expected: held)
        check(vault.holds() == nil, "deleting the held seed emptied the vault")
        await checkKeyFailure(.missing) { _ = try await created.backupPublicKey() }
        await checkKeyFailure(.missing) { _ = try await openKeyring(vault: vault) }

        // Whatever a vault method throws, a typed failure or an error of the host's own,
        // is the vault's failure: never a success, and nothing the vault held changes.
        let failures: [any Error] = [
            VaultFailure.Locked, VaultFailure.Unavailable, VaultFailure.Other,
            NSError(domain: fixtureText, code: 1, userInfo: [NSLocalizedDescriptionKey: fixtureText]),
        ]
        for failure in failures {
            // Each failed call is made once, and nothing follows it: no retry, no clean-up.
            let loading = MemoryVault(failing: "load", failure: failure)
            loading.importSeed()
            await checkKeyFailure(.vault) { _ = try await openKeyring(vault: loading) }
            check(loading.calls() == ["load"], "the vault's calls around a failed load")

            let adding = MemoryVault(failing: "add", failure: failure)
            await checkKeyFailure(.vault) { _ = try await createKeyring(vault: adding) }
            check(adding.calls() == ["add"], "the vault's calls around a failed add")

            let deleting = MemoryVault(failing: "delete", failure: failure)
            deleting.importSeed()
            await checkKeyFailure(.vault) { try await fixtureVaultDelete(vault: deleting, expected: seed()) }
            check(deleting.calls() == ["delete"], "the vault's calls around a failed delete")
        }

        let imported = MemoryVault()
        imported.importSeed()
        await checkKeyFailure(.occupied) { _ = try await createKeyring(vault: imported) }
        let identity = try await openKeyring(vault: imported)
        check(identity.pubkyId() == pubkyId, "the imported identity's Pubky ID")
        let backup = try await identity.backupPublicKey()
        check(backup.publicKey.count == 32 && backup.keyId.count == 8, "the backup key's lengths")
        // A keyring stays bound to the identity it opened.
        imported.replace(Data(repeating: 5, count: 32))
        await checkKeyFailure(.mismatch) { _ = try await identity.backupPublicKey() }
        check(identity.pubkyId() == pubkyId, "the keyring's identity once the vault holds another")

        // A load of another length is the vault's failure.
        for length in [31, 33] {
            let odd = MemoryVault()
            odd.importSeed()
            odd.loads(length)
            await checkKeyFailure(.vault) { _ = try await openKeyring(vault: odd) }
        }
        // A synchronous Swift callback can't start an asynchronous call on its own thread,
        // so the refusal of one has no check here: the Kotlin host has it.
    } catch {
        check(false, "the vault refused a valid call")
    }
}
