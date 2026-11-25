// A bound on every wait in this program: each case runs under a deadline, and a case that
// passes it is named, the stacks of this process and of its store children are printed,
// and the program fails. A hang becomes a failure that says where.
import Darwin
import Foundation

// How long one case, or one step of a case, may take.
let caseBound: TimeInterval = 120

// How long a stack sample may take before it is given up.
private let sampleBound: TimeInterval = 30

/// Write a line to standard error, which is unbuffered: it is out before a hang.
func say(_ line: String) {
    FileHandle.standardError.write("\(line)\n".data(using: .utf8)!)
}

final class Watchdog: @unchecked Sendable {
    private let lock = NSLock()
    private var label = "starting"
    private var deadline = ProcessInfo.processInfo.systemUptime + caseBound
    private var children = Set<Int32>()
    private var started = false

    /// Watch from a thread of its own, so a blocked caller can't hold the watch up.
    func start(_ name: String) {
        lock.lock()
        defer { lock.unlock() }
        label = name
        deadline = ProcessInfo.processInfo.systemUptime + caseBound
        if started { return }
        started = true
        let watch = self
        Thread.detachNewThread { watch.watch() }
    }

    /// Name the step now running and give it a bound of its own.
    func enter(_ name: String) {
        lock.lock()
        label = name
        deadline = ProcessInfo.processInfo.systemUptime + caseBound
        lock.unlock()
        say("start: \(name)")
    }

    /// A store child this process started: sampled and killed if a case runs over.
    func adopt(_ pid: Int32) {
        lock.lock()
        defer { lock.unlock() }
        children.insert(pid)
    }

    func forget(_ pid: Int32) {
        lock.lock()
        defer { lock.unlock() }
        children.remove(pid)
    }

    private func watch() {
        while true {
            Thread.sleep(forTimeInterval: 1)
            lock.lock()
            let late = ProcessInfo.processInfo.systemUptime > deadline
            let name = label
            let running = children
            lock.unlock()
            if late { fail(name, running) }
        }
    }

    private func fail(_ name: String, _ running: Set<Int32>) -> Never {
        say("timed out after \(Int(caseBound)) s: \(name) (process \(getpid()))")
        for pid in [getpid()] + running.sorted() { sample(pid) }
        for pid in running { _ = Darwin.kill(pid, SIGKILL) }
        // Not exit: its handlers could wait on what is stuck.
        _exit(1)
    }

    // Print the stacks of every thread of `pid`, as the system's sampler gives them.
    private func sample(_ pid: Int32) {
        let report = FileManager.default.temporaryDirectory
            .appendingPathComponent("host-sample-\(pid)-\(UUID().uuidString).txt")
        let sampler = Process()
        sampler.executableURL = URL(fileURLWithPath: "/usr/bin/sample")
        sampler.arguments = [String(pid), "2", "-mayDie", "-file", report.path]
        sampler.standardOutput = FileHandle.nullDevice
        sampler.standardError = FileHandle.nullDevice
        do {
            try sampler.run()
        } catch {
            say("no stack sample of process \(pid)")
            return
        }
        let deadline = ProcessInfo.processInfo.systemUptime + sampleBound
        while sampler.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        if sampler.isRunning { _ = Darwin.kill(sampler.processIdentifier, SIGKILL) }
        guard let text = try? String(contentsOf: report, encoding: .utf8) else {
            say("no stack sample of process \(pid)")
            return
        }
        say("stacks of process \(pid):\n\(text)")
        try? FileManager.default.removeItem(at: report)
    }
}

let watchdog = Watchdog()

/// Run one case under its own bound, with a line before and after it, on the caller's actor.
func step(
    _ name: String, isolation: isolated (any Actor)? = #isolation, _ body: () async throws -> Void
) async rethrows {
    watchdog.enter(name)
    try await body()
    say("done: \(name)")
}
