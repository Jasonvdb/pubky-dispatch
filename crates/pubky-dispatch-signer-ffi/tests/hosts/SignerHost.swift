// The Swift host's checks of the signer's life cycle.
import Darwin
import Foundation
import PubkyDispatchSigner

private let signerOrigin = "https://dispatch.example"
private let signerChildMarker = "--signer-child"

private func signerVault() -> MemoryVault {
    let vault = MemoryVault()
    vault.importSeed()
    return vault
}

private func signerFailure(
    _ expected: SignerFfiError, _ what: String, _ call: () async throws -> Void
) async throws {
    do {
        try await call()
        check(false, "expected failure: \(what)")
    } catch let failure as SignerFfiError {
        check(failure == expected, what)
    }
}

private let signerClosedError = SignerFfiError.InvalidInput(reason: "the signer is closed")

/// End the signer, and check that it is closed: every call after it is refused.
private func signerEnd(_ signer: Signer) async throws {
    try await signer.shutdown()
    try await signerFailure(signerClosedError, "shutdown closed the signer") { _ = try signer.status() }
}

private func signerRefusal(_ kind: RefusalKind) -> SignerFfiError {
    .Refused(kind: kind, sinceMs: nil, version: nil, toApp: nil, install: nil, stop: nil,
             measurements: nil, alert: nil, scopes: nil)
}

/// The child holds its newly created signer until the process ends (Dispatch spec 4.3).
func signerHostChild(_ args: [String]) async -> Bool {
    guard args.first == signerChildMarker else { return false }
    check(args.count == 3 && args.last == "hold", "signer child arguments")
    let root = URL(fileURLWithPath: args[1], isDirectory: true)
    // The watchdog bounds the whole child, its wait for its parent's word included.
    watchdog.enter("signer child \(getpid()): hold")
    do {
        try registerSampleProtocol()
        let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
        let signer = try await service.createSigner(vault: signerVault(), store: FileStore(root), origin: signerOrigin)
        let id = try signer.installId()
        // Standard output is the child's channel to its parent: the parent reads this line
        // as the install ID.
        try FileHandle.standardOutput.write(contentsOf: Data((id.base64EncodedString() + "\n").utf8))
        try Data().write(to: root.appendingPathComponent("ready"))
        // EOF frees the signer if its parent exits.
        _ = try FileHandle.standardInput.read(upToCount: 1)
        try await signerEnd(signer)
    } catch {
        check(false, "signer child failed")
    }
    return true
}

private func signerEnroll(_ root: URL) async throws {
    let vault = signerVault()
    let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
    let signer = try await service.createSigner(vault: vault, store: FileStore(root), origin: signerOrigin)
    check(try signer.status() == .enrolling, "created signer is enrolling")
    check(service.enrollments() == 0, "creation sent no enrollment")
    try await signer.resume()
    check(try signer.status() == .signing, "resumed signer is signing")
    let keyring = try await openKeyring(vault: vault)
    let identity = try signer.identity()
    check(identity.count == 32 && identity == keyring.publicKey(), "signer identity")
    check(try signer.installId().count == 16, "install ID length")
    // Neither a status nor the signer's handle describes what it holds.
    let recovering = SignerStatus.recovering(origin: "https://private.example")
    check(String(describing: recovering) == "SignerStatus(<redacted>)" &&
          String(reflecting: recovering) == "SignerStatus(<redacted>)", "a status's description")
    check(!String(reflecting: signer).contains(identity.base64EncodedString()) &&
          String(reflecting: signer).hasPrefix("PubkyDispatchSigner.Signer"), "the signer's description")
    try await signerEnd(signer)
    let reopened = try await service.openSigner(vault: vault, store: FileStore(root))
    check(try reopened.status() == .signing, "reopened signer is signing")
    check(try reopened.identity() == identity, "reopened signer's identity")
    try await signerEnd(reopened)
}

private func signerInterrupted(_ root: URL) async throws {
    let vault = signerVault()
    let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
    let signer = try await service.createSigner(vault: vault, store: FileStore(root), origin: signerOrigin)
    let install = try signer.installId()
    service.loseNextEnrollAnswer()
    let timeout = SignerFfiError.Service(kind: .transport, status: nil, authenticated: false, code: nil,
                                         retryAfterS: nil, retry: nil, notHosted: false, knownVersion: nil,
                                         transport: .timeout, limit: nil, generation: nil, serverTimeMs: nil,
                                         detail: nil)
    try await signerFailure(timeout, "lost enrollment answer") { try await signer.resume() }
    try await signerEnd(signer)
    let reopened = try await service.openSigner(vault: vault, store: FileStore(root))
    check(try reopened.installId() == install, "install ID after lost answer")
    try await reopened.resume()
    check(try reopened.status() == .signing, "resumed interrupted enrollment")
    check(service.enrollments() == 1, "one distinct enrollment")
    try await signerEnd(reopened)
}

private func signerKilledOwner(_ root: URL) async throws {
    let child = Process()
    child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    child.arguments = [signerChildMarker, root.path, "hold"]
    child.environment = ProcessInfo.processInfo.environment
    child.standardInput = Pipe()
    let output = Pipe()
    child.standardOutput = output
    try child.run()
    watchdog.adopt(child.processIdentifier)
    say("signer child \(child.processIdentifier): hold")
    defer {
        // Never `waitUntilExit` from here: it waits on this thread's run loop for a notice
        // that wakes the thread the child was launched from, which a task may have left.
        if child.isRunning { _ = Darwin.kill(child.processIdentifier, SIGKILL) }
        let deadline = ProcessInfo.processInfo.systemUptime + 30
        while child.isRunning {
            check(ProcessInfo.processInfo.systemUptime < deadline, "signer child outlived its kill")
            usleep(20_000)
        }
        watchdog.forget(child.processIdentifier)
    }

    let ready = root.appendingPathComponent("ready")
    let deadline = ProcessInfo.processInfo.systemUptime + 30
    while !FileManager.default.fileExists(atPath: ready.path) {
        check(child.isRunning, "signer child exited before creating")
        check(ProcessInfo.processInfo.systemUptime < deadline, "signer child timed out")
        try await Task.sleep(nanoseconds: 20_000_000)
    }

    let vault = signerVault()
    let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
    try await signerFailure(.Store(kind: .inUse, size: nil, cap: nil), "child owns signer") {
        _ = try await service.openSigner(vault: vault, store: FileStore(root))
    }
    // The marker follows a single pipe write containing the whole ID.
    let line = String(decoding: output.fileHandleForReading.availableData, as: UTF8.self)
    let install = Data(base64Encoded: line.trimmingCharacters(in: .newlines))
    check(install?.count == 16, "child's install ID length")
    // SIGKILL: the child ends without running any of its own code.
    check(Darwin.kill(child.processIdentifier, SIGKILL) == 0, "kill the owning signer")
    let killed = ProcessInfo.processInfo.systemUptime + 30
    while child.isRunning && ProcessInfo.processInfo.systemUptime < killed {
        try await Task.sleep(nanoseconds: 20_000_000)
    }
    check(!child.isRunning && child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGKILL,
          "signer child killed")

    let reopened = try await service.openSigner(vault: vault, store: FileStore(root))
    check(try reopened.installId() == install, "killed signer's install ID")
    check(try reopened.status() == .enrolling, "killed signer kept its enrollment")
    try await reopened.resume()
    check(try reopened.status() == .signing, "resumed killed signer")
    try await signerEnd(reopened)
}

private func signerProduction(_ root: URL) async throws {
    let vault = signerVault()
    let store = FileStore(root)
    let home = MemoryHomeserver()
    let environment = try SignerEnvironment(homeserver: home, transport: TransportOptions())
    let origin = "https://service.example"
    try await signerFailure(signerRefusal(.notSetUp), "empty store refusal") {
        _ = try await environment.openSigner(vault: vault, store: store)
    }
    let signer = try await environment.createSigner(vault: vault, store: store, origin: origin)
    check(try signer.status() == .enrolling, "offline creation")
    try await signerEnd(signer)
    try await signerFailure(signerRefusal(.alreadySetUp), "existing store refusal") {
        _ = try await environment.createSigner(vault: vault, store: store, origin: origin)
    }
    check(await home.calls.isEmpty, "offline setup made no homeserver call")
}

private func signerClosedCalls(_ root: URL) async throws {
    let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
    let signer = try await service.createSigner(vault: signerVault(), store: FileStore(root), origin: signerOrigin)
    try await signer.shutdown()
    let closed = signerClosedError
    try await signerFailure(closed, "resume after shutdown") { try await signer.resume() }
    try await signerFailure(closed, "status after shutdown") { _ = try signer.status() }
    try await signerFailure(closed, "identity after shutdown") { _ = try signer.identity() }
    try await signerFailure(closed, "install ID after shutdown") { _ = try signer.installId() }
    try await signerFailure(closed, "second shutdown") { try await signer.shutdown() }
}

// The last handle goes without a shutdown (here, Swift's release of the last reference): the
// signer is dropped as it is, its hold on the store's records goes with it, and the next open
// takes them.
private func signerDropped(_ root: URL) async throws {
    let vault = signerVault()
    let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
    var signer: Signer? = try await service.createSigner(vault: vault, store: FileStore(root), origin: signerOrigin)
    let install = try signer?.installId()
    signer = nil
    let reopened = try await service.openSigner(vault: vault, store: FileStore(root))
    check(try reopened.installId() == install, "install ID after a dropped signer")
    check(try reopened.status() == .enrolling, "dropped signer kept its enrollment")
    try await signerEnd(reopened)
}

// A signer whose handle was lost, as a cancelled call can lose it, holds the store's records
// until the host ends it through the store.
private func signerLostHandle(_ root: URL) async throws {
    let vault = signerVault()
    let service = try FixtureService(seed: seed(), homeserver: MemoryHomeserver())
    try await service.createSignerLosingHandle(vault: vault, store: FileStore(root), origin: signerOrigin)
    try await signerFailure(.Store(kind: .inUse, size: nil, cap: nil), "lost signer owns the store") {
        _ = try await service.openSigner(vault: vault, store: FileStore(root))
    }
    try await shutdownSigners(store: FileStore(root))
    let reopened = try await service.openSigner(vault: vault, store: FileStore(root))
    check(try reopened.status() == .enrolling, "the ended signer kept its enrollment")
    try await shutdownSigners(store: FileStore(root))
    try await signerFailure(signerClosedError, "ending the store's signers closed the handle") {
        _ = try reopened.status()
    }
}

/// Check the signer's life cycle (Dispatch spec 4.3).
func checkSigner() async {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    var completed = 0
    func run(_ name: String, _ test: (URL) async throws -> Void) async throws {
        let directory = root.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        try await step("signer: \(name)") { try await test(directory) }
        completed += 1
    }
    do {
        try registerSampleProtocol()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        try await run("enroll", signerEnroll)
        try await run("interrupted", signerInterrupted)
        try await run("killed", signerKilledOwner)
        try await run("production", signerProduction)
        try await run("closed", signerClosedCalls)
        try await run("dropped", signerDropped)
        try await run("lost", signerLostHandle)
        check(completed == 7, "every signer check ran")
    } catch {
        check(false, "unexpected signer failure")
    }
}
