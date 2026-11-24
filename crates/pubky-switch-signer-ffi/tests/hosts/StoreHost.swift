// The host's durable store checks (Switch spec 13.2).
import CryptoKit
import Darwin
import Foundation
import PubkySwitchSigner

// An open file. With O_EXLOCK it holds the file's exclusive lock until it is closed;
// with O_NONBLOCK as well, it is nil while another descriptor holds that lock.
private final class Descriptor {
    let fd: Int32

    init?(_ url: URL, _ flags: Int32) throws {
        while true {
            let fd = Darwin.open(url.path, flags | O_CLOEXEC, 0o600)
            if fd >= 0 {
                self.fd = fd
                return
            }
            switch errno {
            case EINTR: continue
            case EWOULDBLOCK where flags & O_NONBLOCK != 0: return nil
            default: throw StoreFailure.Unavailable
            }
        }
    }

    deinit { _ = Darwin.close(fd) }
}

private func open(_ url: URL, _ flags: Int32) throws -> Descriptor {
    guard let descriptor = try Descriptor(url, flags) else { throw StoreFailure.Unavailable }
    return descriptor
}

private let valueCap: UInt64 = 16 << 20
private let batchCap: UInt64 = 32 << 20

private func namespaces(_ writes: [StoreWrite], condition: Data? = nil) throws -> Set<Data> {
    var touched = Set<Data>()
    var size: UInt64 = 0
    func charge(_ bytes: Int) {
        let (total, overflow) = size.addingReportingOverflow(UInt64(bytes))
        size = overflow ? UInt64.max : total
    }
    func checkSize() throws {
        guard size <= batchCap else { throw StoreFailure.TooLarge(size: size, cap: batchCap) }
    }
    if let condition {
        charge(condition.count)
        charge(32)
        try checkSize()
    }
    for write in writes {
        let ns: String
        switch write {
        case let .put(name, key, value):
            ns = name
            let length = UInt64(value.count)
            guard length <= valueCap else { throw StoreFailure.TooLarge(size: length, cap: valueCap) }
            charge(value.count)
            charge(key.count)
        case let .delete(name, key):
            ns = name
            charge(key.count)
        case let .deletePrefix(name, prefix):
            ns = name
            charge(prefix.count)
        @unknown default: throw StoreFailure.Other
        }
        let name = Data(ns.utf8)
        guard condition == nil || condition == name else { throw StoreFailure.Other }
        charge(name.count)
        try checkSize()
        touched.insert(name)
    }
    return touched
}

// A single snapshot covers every namespace. Each flock stays on its own stable inode.
// Use encrypted, backup-excluded storage on a device. The temporary directory holds test records.
private final class FileStore: HostStore, @unchecked Sendable {
    private typealias Records = [Data: [Data: Data]]
    private let root: URL
    // Access to both fields is serialized by the transaction lock.
    private var owners = [Data: (token: Data, lock: Descriptor)]()
    private var unknownAfterWrite = false

    init(_ root: URL) { self.root = root }

    private func transaction<T>(_ body: () throws -> T) throws -> T {
        let lock = try open(root.appendingPathComponent("transaction.lock"), O_RDWR | O_CREAT | O_EXLOCK)
        return try withExtendedLifetime(lock) { try body() }
    }

    private func namespaceLock(_ name: Data) throws -> Descriptor? {
        let digest = SHA256.hash(data: name).map { String(format: "%02x", $0) }.joined()
        return try Descriptor(
            root.appendingPathComponent(digest + ".lock"), O_RDWR | O_CREAT | O_EXLOCK | O_NONBLOCK
        )
    }

    func acquire(ns: String, owner: Data) throws -> StoreAcquire {
        guard owner.count == 32 else { throw StoreFailure.Other }
        return try transaction {
            let name = Data(ns.utf8)
            guard let lock = try namespaceLock(name) else { return .busy }
            owners[name] = (owner, lock)
            return .acquired
        }
    }

    func release(ns: String, owner: Data) throws {
        guard owner.count == 32 else { throw StoreFailure.Other }
        try transaction {
            let name = Data(ns.utf8)
            if owners[name]?.token == owner { owners[name] = nil }
        }
    }

    func forget(_ ns: String) throws {
        try transaction { owners[Data(ns.utf8)] = nil }
    }

    func loseNextCommitReply() throws {
        try transaction { unknownAfterWrite = true }
    }

    private var snapshot: URL { root.appendingPathComponent("records") }

    private func read() throws -> Records {
        let data: Data
        do {
            data = try Data(contentsOf: snapshot)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return [:]
        } catch {
            throw StoreFailure.Unavailable
        }
        do {
            return try PropertyListDecoder().decode(Records.self, from: data)
        } catch {
            throw StoreFailure.Corrupt
        }
    }

    func get(ns: String, key: Data) throws -> Data? {
        try transaction { try read()[Data(ns.utf8)]?[key] }
    }

    func scan(ns: String, prefix: Data, after: Data?, limit: UInt32) throws -> [StoreEntry] {
        try transaction {
            let entries = try read()[Data(ns.utf8)] ?? [:]
            return entries.filter { entry in
                entry.key.starts(with: prefix) && (after.map { $0.lexicographicallyPrecedes(entry.key) } ?? true)
            }.sorted { $0.key.lexicographicallyPrecedes($1.key) }
                .prefix(Int(limit)).map { StoreEntry(key: $0.key, value: $0.value) }
        }
    }

    private func apply(_ writes: [StoreWrite]) throws {
        var records = try read()
        for write in writes {
            switch write {
            case let .put(ns, key, value): records[Data(ns.utf8), default: [:]][key] = value
            case let .delete(ns, key): records[Data(ns.utf8)]?[key] = nil
            case let .deletePrefix(ns, prefix):
                let name = Data(ns.utf8)
                records[name] = records[name]?.filter { !$0.key.starts(with: prefix) }
            @unknown default: throw StoreFailure.Other
            }
        }
        let bytes: Data
        do {
            bytes = try PropertyListEncoder().encode(records)
        } catch {
            throw StoreFailure.Unavailable
        }
        // Written and synchronized through one descriptor, so a failed write-back is reported
        // here, before the rename publishes the snapshot.
        let next = root.appendingPathComponent("records.next")
        let file = try open(next, O_WRONLY | O_CREAT | O_TRUNC)
        let directory = try open(root, O_RDONLY)
        defer { withExtendedLifetime((file, directory)) {} }
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count, let base = raw.baseAddress {
                let written = Darwin.write(file.fd, base + offset, raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw StoreFailure.Unavailable
                }
                offset += written
            }
        }
        guard Darwin.fcntl(file.fd, F_FULLFSYNC) == 0,
              Darwin.rename(next.path, snapshot.path) == 0 else { throw StoreFailure.Unavailable }
        guard Darwin.fsync(directory.fd) == 0 else { throw StoreFailure.Unknown }
    }

    func commit(writes: [StoreWrite]) throws {
        try transaction {
            for ns in try namespaces(writes) {
                // Acquisition takes the same transaction lock, so a namespace that is
                // free here stays free through snapshot replacement and synchronization.
                guard try namespaceLock(ns) != nil else { throw StoreFailure.InUse }
            }
            try apply(writes)
        }
    }

    func commitIf(ns: String, owner: Data, writes: [StoreWrite]) throws -> StoreCommit {
        guard owner.count == 32 else { throw StoreFailure.Other }
        return try transaction {
            let name = Data(ns.utf8)
            _ = try namespaces(writes, condition: name)
            guard owners[name]?.token == owner else { return .notOwner }
            try apply(writes)
            if unknownAfterWrite {
                unknownAfterWrite = false
                throw StoreFailure.Unknown
            }
            return .applied
        }
    }
}

private let childMarker = "--store-child"
private let busyStatus: Int32 = 23
private let childKey = Data([9])

private func withChild(
    _ root: URL, _ ns: String, _ action: String, _ body: (Process) async throws -> Void
) async throws {
    let child = Process()
    child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    child.arguments = [childMarker, root.path, ns, action]
    child.environment = ProcessInfo.processInfo.environment
    child.standardInput = Pipe()
    try child.run()
    defer {
        if child.isRunning { _ = Darwin.kill(child.processIdentifier, SIGKILL) }
        child.waitUntilExit()
    }
    try await body(child)
}

private func waitForExit(_ child: Process) async throws {
    let deadline = ProcessInfo.processInfo.systemUptime + 30
    while child.isRunning {
        check(ProcessInfo.processInfo.systemUptime < deadline, "store child timed out")
        try await Task.sleep(nanoseconds: 20_000_000)
    }
    child.waitUntilExit()
}

/// Handle the second process of a store check (Switch spec 13.2).
func storeHostChild(_ args: [String]) async -> Bool {
    guard args.first == childMarker else { return false }
    check(args.count == 4, "store child arguments")
    let root = URL(fileURLWithPath: args[1], isDirectory: true)
    let ns = args[2]
    let action = args[3]
    let store = FileStore(root)
    do {
        if action == "busy" {
            let probe: StoreProbe
            do {
                probe = try await storeProbe(store: store, namespace: ns)
            } catch StoreFailure.InUse {
                exit(busyStatus)
            }
            try await probe.closeStore()
            return true
        }
        check(action == "hold" || action == "write", "store child action")
        let probe = try await storeProbe(store: store, namespace: ns)
        try await probe.put(key: childKey, value: Data(action.utf8))
        if action == "hold" {
            try Data().write(to: root.appendingPathComponent("ready"))
            // EOF also lets the child exit if the parent dies.
            _ = try FileHandle.standardInput.read(upToCount: 1)
        }
        try await probe.closeStore()
    } catch {
        check(false, "store child failed")
    }
    return true
}

private func refused(
    _ expected: StoreFailure, _ what: String, _ call: () async throws -> Void
) async throws {
    do {
        try await call()
        check(false, what)
    } catch let failure as StoreFailure {
        check(failure == expected, what)
    }
}

private func test_store_process_ownership(_ root: URL, _ ns: String, _ store: FileStore) async throws {
    let probe = try await storeProbe(store: store, namespace: ns)
    try await withChild(root, ns, "busy") { child in
        try await waitForExit(child)
        check(child.terminationReason == .exit && child.terminationStatus == busyStatus, "child saw the owner")
    }
    try await probe.closeStore()
    try await refused(.NotOwner, "closed probe") { _ = try await probe.get(key: childKey) }
    try await withChild(root, ns, "write") { child in
        try await waitForExit(child)
        check(child.terminationReason == .exit && child.terminationStatus == 0, "child acquired after close")
    }
    let reopened = try await storeProbe(store: store, namespace: ns)
    check(try await reopened.get(key: childKey) == Data("write".utf8), "child's durable write")
    try await reopened.closeStore()

    try await withChild(root, ns, "hold") { child in
        let deadline = ProcessInfo.processInfo.systemUptime + 30
        let ready = root.appendingPathComponent("ready")
        while !FileManager.default.fileExists(atPath: ready.path) {
            check(child.isRunning, "holder exited before committing")
            check(ProcessInfo.processInfo.systemUptime < deadline, "holder timed out")
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        try await refused(.InUse, "child still owns the namespace") {
            _ = try await storeProbe(store: store, namespace: ns)
        }
        check(Darwin.kill(child.processIdentifier, SIGKILL) == 0, "kill the owning child")
        try await waitForExit(child)
        check(child.terminationReason == .uncaughtSignal && child.terminationStatus == SIGKILL, "holder died without closing")
    }
    let afterKill = try await storeProbe(store: store, namespace: ns)
    check(try await afterKill.get(key: childKey) == Data("hold".utf8), "killed owner's durable write")
    try await afterKill.closeStore()
}

private func test_store_records(_ root: URL, _ ns: String, _ store: FileStore) async throws {
    let low = Data([7, 0]), middle = Data([7, 127]), high = Data([7, 255])
    try await storeUnownedPut(store: store, namespace: ns, key: low, value: low)
    let probe = try await storeProbe(store: store, namespace: ns)
    for key in [high, middle, childKey] { try await probe.put(key: key, value: key) }
    let page = try await probe.scan(prefix: Data([7]), after: nil, limit: 2)
    check(page.map(\.key) == [low, middle], "ordered page")
    let tail = try await probe.scan(prefix: Data([7]), after: middle, limit: 1)
    check(tail.map(\.key) == [high] && tail.first?.value == high, "exclusive cursor")
    check(try await probe.get(key: high) == high, "record value")
    check(page.allSatisfy { String(reflecting: $0) == "StoreEntry(<redacted>)" }, "scan entry description")
    let other = FileStore(root)
    try await refused(.Other, "short owner refused") { try other.release(ns: ns, owner: Data([1])) }
    try await refused(.InUse, "second local handle") { _ = try await storeProbe(store: other, namespace: ns) }
    try await refused(.InUse, "raw write to an owned namespace") {
        try await storeUnownedPut(store: other, namespace: ns, key: low, value: high)
    }
    let writes: [StoreWrite] = [.put(ns: "other", key: low, value: high), .delete(ns: ns, key: low)]
    check(writes.allSatisfy { String(reflecting: $0) == "StoreWrite(<redacted>)" }, "write description")
    try await refused(.InUse, "whole raw batch") { try other.commit(writes: writes) }
    check(try other.get(ns: "other", key: low) == nil, "raw batch left other namespace alone")
    check(try await probe.get(key: low) == low, "raw batch left owned namespace alone")
    try await probe.deletePrefix(prefix: Data([7]))
    check(try await probe.scan(prefix: Data([7]), after: nil, limit: 4).isEmpty, "prefix deletion")
    check(try await probe.get(key: childKey) == childKey, "prefix deletion preserved other keys")
    try await probe.closeStore()
    try store.commit(writes: [.delete(ns: ns, key: childKey)])
    check(try store.get(ns: ns, key: childKey) == nil, "exact deletion")
}

private func test_store_commit_outcomes(_ ns: String, _ store: FileStore) async throws {
    let stale = try await storeProbe(store: store, namespace: ns)
    try store.forget(ns)
    let current = try await storeProbe(store: store, namespace: ns)
    let key = Data([42])
    try await refused(.NotOwner, "stale commit") { try await stale.put(key: key, value: key) }
    try await refused(.NotOwner, "stale read") { _ = try await stale.get(key: key) }
    check(try await current.get(key: key) == nil, "stale commit changed nothing")
    try await refused(.NotOwner, "closing a stale probe") { try await stale.closeStore() }
    try await refused(.InUse, "stale release preserved current ownership") {
        _ = try await storeProbe(store: store, namespace: ns)
    }
    try store.loseNextCommitReply()
    try await refused(.Unknown, "ambiguous commit") { try await current.put(key: key, value: key) }
    check(try await current.get(key: key) == key, "unknown commit was applied")
    try await current.closeStore()
}

/// Check ordered records, durable commits and exclusive ownership (Switch spec 13.2).
func checkStore() async {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    do {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let ns = "signer/test"
        let store = FileStore(root)
        try await test_store_records(root, ns, store)
        try await test_store_process_ownership(root, ns, store)
        try await test_store_commit_outcomes(ns, store)
    } catch {
        check(false, "host store operation failed")
    }
}
