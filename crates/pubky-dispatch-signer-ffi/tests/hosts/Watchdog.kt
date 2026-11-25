// A bound on every wait in this program: each case runs under a deadline, and a case that
// passes it is named, the stacks of every thread are printed, its store children are
// killed, and the program fails. A hang becomes a failure that says where.
package pubky.dispatch.signer.tests

import java.util.concurrent.TimeUnit

// How long one case, or one step of a case, may take.
val CASE_BOUND_NANOS: Long = TimeUnit.SECONDS.toNanos(120)

object Watchdog {
    private val lock = Any()
    private var label = "starting"
    private var deadline = System.nanoTime() + CASE_BOUND_NANOS
    private var started = false

    /** Watch from a daemon thread of its own, so a blocked caller can't hold the watch up. */
    fun start(name: String) = synchronized(lock) {
        label = name
        deadline = System.nanoTime() + CASE_BOUND_NANOS
        if (started) return@synchronized
        started = true
        val thread = Thread(::watch, "watchdog")
        thread.isDaemon = true
        thread.start()
    }

    /** Name the step now running and give it a bound of its own. */
    fun enter(name: String) {
        synchronized(lock) {
            label = name
            deadline = System.nanoTime() + CASE_BOUND_NANOS
        }
        System.err.println("start: $name")
    }

    private fun watch() {
        while (true) {
            Thread.sleep(1000)
            val late = synchronized(lock) { if (System.nanoTime() - deadline > 0) label else null }
            if (late != null) fail(late)
        }
    }

    private fun fail(name: String) {
        val bound = TimeUnit.NANOSECONDS.toSeconds(CASE_BOUND_NANOS)
        System.err.println("timed out after $bound s: $name (process ${ProcessHandle.current().pid()})")
        for ((thread, frames) in Thread.getAllStackTraces()) {
            System.err.println("thread \"${thread.name}\" ${thread.state}")
            for (frame in frames) System.err.println("    at $frame")
        }
        ProcessHandle.current().descendants().forEach { it.destroyForcibly() }
        System.err.flush()
        // Not exit: its shutdown hooks could wait on what is stuck.
        Runtime.getRuntime().halt(1)
    }
}

/** Run one case under its own bound, with a line before and after it. */
suspend fun step(name: String, body: suspend () -> Unit) {
    Watchdog.enter(name)
    body()
    System.err.println("done: $name")
}
