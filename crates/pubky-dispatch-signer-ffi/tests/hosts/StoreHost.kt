// The host's durable store checks (Dispatch spec 3.1).
package pubky.dispatch.signer.tests

import java.io.IOException
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.TRUNCATE_EXISTING
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat
import java.util.InvalidPropertiesFormatException
import java.util.Properties
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import com.sun.jna.Native
import kotlin.system.exitProcess
import pubky.dispatch.signer.HostStore
import pubky.dispatch.signer.StoreAcquire
import pubky.dispatch.signer.StoreCommit
import pubky.dispatch.signer.StoreEntry
import pubky.dispatch.signer.StoreFailure
import pubky.dispatch.signer.StoreWrite
import pubky.dispatch.signer.openStoreSession
import pubky.dispatch.signer.releaseOwedLocks
import pubky.dispatch.signer.storeUnownedCommit

private val hex = HexFormat.of()
private const val valueCap = 16L shl 20
private const val batchCap = 32L shl 20

// Each kind of write carries its namespace; this reads it from any of them.
private val StoreWrite.writtenNamespace: String get() = when (this) {
    is StoreWrite.Put -> namespace
    is StoreWrite.Delete -> namespace
    is StoreWrite.DeletePrefix -> namespace
}

private fun checkBatch(writes: List<StoreWrite>, ns: String? = null) {
    var size = ns?.let { it.encodeToByteArray().size.toLong() + 32L } ?: 0L
    for (write in writes) {
        if (ns != null && ns != write.writtenNamespace) throw StoreFailure.Other()
        size += write.writtenNamespace.encodeToByteArray().size
        size += when (write) {
            is StoreWrite.Put -> {
                val length = write.value.size.toLong()
                if (length > valueCap) throw StoreFailure.TooLarge(length.toULong(), valueCap.toULong())
                length + write.key.size
            }
            is StoreWrite.Delete -> write.key.size.toLong()
            is StoreWrite.DeletePrefix -> write.prefix.size.toLong()
        }
        if (size > batchCap) throw StoreFailure.TooLarge(size.toULong(), batchCap.toULong())
    }
    if (size > batchCap) throw StoreFailure.TooLarge(size.toULong(), batchCap.toULong())
}

private fun checkOwner(owner: ByteArray) {
    if (owner.size != 32) throw StoreFailure.Other()
}

private class HeldLock(val owner: ByteArray, val lock: FileLock)

// A single replaceable snapshot holds all namespaces. Neither the transaction lock nor
// a namespace lock is ever replaced. Use encrypted, backup-excluded storage on a device.
// The temporary directory holds test records.
//
// Java's file locks belong to the whole JVM, not to a channel: a second lock on the same
// file in this JVM is refused with an exception, and closing any channel on it can drop
// the lock. So, unlike the Swift host's per-descriptor locks, exclusion inside this JVM is
// a table shared by every instance, keyed by the lock file, which is consulted before a
// lock file is ever opened again; the operating-system lock excludes other processes.
// The checks within one process therefore test that table, and the two-process checks the
// operating-system lock.
private class FileStore(directory: Path) : HostStore {
    private val root = directory.toRealPath()
    private val records = root.resolve("records")
    val unknownAfterWrite = AtomicBoolean()
    val failNextRelease = AtomicBoolean()
    // The call that next throws an `Error`, not an `Exception`: "commitIf" or "release".
    val errorOn = AtomicReference<String?>()

    companion object {
        // POSIX record locks belong to the JVM. Even closing a second channel for the
        // same inode can release its lock. Consult this table before opening that file.
        private val owners = mutableMapOf<Path, HeldLock>()
    }

    // The transaction lock, waited for within a bound: a holder that never lets go fails
    // the program here, by name, rather than holding this call and its thread for good.
    private fun <T> transaction(body: () -> T): T = synchronized(owners) {
        try {
            FileChannel.open(root.resolve("transaction.lock"), CREATE, WRITE).use { file ->
                val started = System.nanoTime()
                var held = file.tryLock()
                while (held == null) {
                    if (System.nanoTime() - started > TimeUnit.SECONDS.toNanos(30)) {
                        System.err.println("failed: the store's transaction lock was held over 30 s")
                        Runtime.getRuntime().halt(1)
                    }
                    Thread.sleep(5)
                    held = file.tryLock()
                }
                held.use { body() }
            }
        } catch (failure: StoreFailure) {
            throw failure
        } catch (_: Exception) {
            throw StoreFailure.Unknown()
        }
    }

    private fun lockPath(ns: String): Path {
        val digest = MessageDigest.getInstance("SHA-256").digest(ns.encodeToByteArray())
        return root.resolve(hex.formatHex(digest) + ".lock")
    }

    private fun tryLock(path: Path): FileLock? {
        if (path in owners) return null
        val file = FileChannel.open(path, CREATE, WRITE)
        try {
            return file.tryLock().also { if (it == null) file.close() }
        } catch (failure: Exception) {
            file.close()
            throw failure
        }
    }

    fun holds(namespace: String) = transaction { lockPath(namespace) in owners }

    // Every handle on this directory is a handle of one store.
    override fun storeId(): String = root.toString()

    private fun errorIf(call: String) {
        if (errorOn.compareAndSet(call, null)) throw AssertionError("a store fault")
    }

    override fun acquire(namespace: String, owner: ByteArray): StoreAcquire = transaction {
        checkOwner(owner)
        val path = lockPath(namespace)
        val lock = tryLock(path) ?: return@transaction StoreAcquire.BUSY
        owners[path] = HeldLock(owner.copyOf(), lock)
        StoreAcquire.ACQUIRED
    }

    override fun release(namespace: String, owner: ByteArray): Unit = transaction {
        checkOwner(owner)
        errorIf("release")
        if (failNextRelease.getAndSet(false)) throw StoreFailure.Unavailable()
        val path = lockPath(namespace)
        if (owners[path]?.owner.contentEquals(owner)) forgetLocked(path)
    }

    private fun forgetLocked(path: Path) {
        owners.remove(path)?.lock?.channel()?.close()
    }

    fun forget(ns: String) = transaction { forgetLocked(lockPath(ns)) }

    private fun read(): Properties {
        val snapshot = Properties()
        try {
            Files.newInputStream(records).use { snapshot.loadFromXML(it) }
        } catch (_: NoSuchFileException) {
            return snapshot
        } catch (_: InvalidPropertiesFormatException) {
            throw StoreFailure.Corrupt()
        } catch (_: IOException) {
            throw StoreFailure.Unavailable()
        }
        return snapshot
    }

    private fun keyName(ns: String, key: ByteArray) =
        hex.formatHex(ns.encodeToByteArray()) + "." + hex.formatHex(key)

    private fun decode(value: String): ByteArray = try {
        Base64.getDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw StoreFailure.Corrupt()
    }

    override fun get(namespace: String, key: ByteArray): ByteArray? = transaction {
        read().getProperty(keyName(namespace, key))?.let(::decode)
    }

    override fun scan(namespace: String, prefix: ByteArray, after: ByteArray?, limit: UInt): List<StoreEntry> =
        transaction {
            val snapshot = read()
            val start = keyName(namespace, prefix)
            val cursor = after?.let { keyName(namespace, it) }
            snapshot.stringPropertyNames().asSequence()
                .filter { it.startsWith(start) && (cursor == null || it > cursor) }
                .sorted()
                .take(limit.coerceAtMost(Int.MAX_VALUE.toUInt()).toInt())
                .map { name ->
                    val key = try {
                        hex.parseHex(name.substringAfter('.'))
                    } catch (_: IllegalArgumentException) {
                        throw StoreFailure.Corrupt()
                    }
                    StoreEntry(key, decode(snapshot.getProperty(name)))
                }.toList()
        }

    private fun apply(writes: List<StoreWrite>) {
        val snapshot = read()
        for (write in writes) {
            when (write) {
                is StoreWrite.Put -> snapshot.setProperty(
                    keyName(write.namespace, write.key), Base64.getEncoder().encodeToString(write.value)
                )
                is StoreWrite.Delete -> snapshot.remove(keyName(write.namespace, write.key))
                is StoreWrite.DeletePrefix -> {
                    val prefix = keyName(write.namespace, write.prefix)
                    snapshot.keys.removeIf { (it as String).startsWith(prefix) }
                }
            }
        }
        val next = root.resolve("records.next")
        try {
            // Written and forced through one channel, so a failed write-back is reported here.
            FileChannel.open(next, CREATE, WRITE, TRUNCATE_EXISTING).use { channel ->
                snapshot.storeToXML(Channels.newOutputStream(channel), null)
                channel.force(true)
            }
        } catch (_: IOException) {
            throw StoreFailure.Unavailable()
        }
        Files.move(next, records, ATOMIC_MOVE, REPLACE_EXISTING)
        FileChannel.open(root, READ).use { it.force(true) }
    }

    override fun commit(writes: List<StoreWrite>) = transaction {
        checkBatch(writes)
        // Acquisition also holds the transaction lock, so nobody can take a checked
        // namespace before this snapshot is durable.
        for (namespace in writes.map { it.writtenNamespace }.distinct()) {
            val lock = tryLock(lockPath(namespace)) ?: throw StoreFailure.InUse()
            lock.channel().close()
        }
        apply(writes)
    }

    override fun commitIf(namespace: String, owner: ByteArray, writes: List<StoreWrite>): StoreCommit =
        transaction {
            checkOwner(owner)
            errorIf("commitIf")
            checkBatch(writes, namespace)
            if (!owners[lockPath(namespace)]?.owner.contentEquals(owner)) return@transaction StoreCommit.NOT_OWNER
            apply(writes)
            if (unknownAfterWrite.getAndSet(false)) throw StoreFailure.Unknown()
            StoreCommit.APPLIED
        }
}

private const val childMarker = "--store-child"
private const val busyStatus = 23
private val childKey = byteArrayOf(9)

private fun child(root: Path, ns: String, action: String): Process {
    val java = ProcessHandle.current().info().command().orElseThrow()
    return ProcessBuilder(
        java, "-Djna.library.path=" + System.getProperty("jna.library.path"),
        "-cp", System.getProperty("java.class.path"), "pubky.dispatch.signer.tests.MainKt",
        childMarker, root.toString(), ns, action,
    ).redirectError(ProcessBuilder.Redirect.INHERIT).start().also {
        System.err.println("store child ${it.pid()}: $action")
    }
}

private fun childStatus(process: Process): Int {
    require(process.waitFor(30, TimeUnit.SECONDS), "store child timed out")
    return process.exitValue()
}

private inline fun withChild(root: Path, ns: String, action: String, run: (Process) -> Unit) {
    val process = child(root, ns, action)
    try {
        run(process)
    } finally {
        if (process.isAlive) process.destroyForcibly()
        childStatus(process)
    }
}

/** Handle the second process of a store check (Dispatch spec 3.1). */
suspend fun storeHostChild(args: List<String>): Boolean {
    if (args.firstOrNull() != childMarker) return false
    require(args.size == 4, "store child arguments")
    val (_, directory, ns, action) = args
    Watchdog.enter("store child ${ProcessHandle.current().pid()}: $action")
    val root = Path.of(directory)
    val store = FileStore(root)
    if (action == "busy") {
        val session = try {
            openStoreSession(store, ns)
        } catch (_: StoreFailure.InUse) {
            exitProcess(busyStatus)
        }
        session.end()
        return true
    }
    require(action == "write" || action == "hold", "store child action")
    val session = openStoreSession(store, ns)
    session.put(childKey, action.encodeToByteArray())
    if (action == "hold") {
        Files.createFile(root.resolve("ready"))
        // The parent holds stdin open until it kills us. EOF also frees an orphan.
        System.`in`.read()
    }
    session.end()
    return true
}

private inline fun <reified E : StoreFailure> refused(what: String, call: () -> Unit) {
    try {
        call()
    } catch (error: StoreFailure) {
        require(error is E, what)
        return
    }
    require(false, what)
}

private suspend fun test_store_process_ownership(root: Path, ns: String, store: FileStore) {
    val name = "test_store_process_ownership"
    Watchdog.enter("$name: a child is refused while this process owns")
    val session = openStoreSession(store, ns)
    withChild(root, ns, "busy") { require(childStatus(it) == busyStatus, "child saw the owner") }
    session.end()
    Watchdog.enter("$name: a child acquires after the end")
    refused<StoreFailure.NotOwner>("ended session") { session.get(childKey) }
    withChild(root, ns, "write") { require(childStatus(it) == 0, "child acquired after close") }
    val reopened = openStoreSession(store, ns)
    require(reopened.get(childKey).contentEquals("write".encodeToByteArray()), "child's durable write")
    reopened.end()

    Watchdog.enter("$name: a killed owner")
    withChild(root, ns, "hold") { holder ->
        val started = System.nanoTime()
        while (!Files.exists(root.resolve("ready"))) {
            require(holder.isAlive, "holder exited before committing")
            require(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(30), "holder timed out")
            Thread.sleep(20)
        }
        refused<StoreFailure.InUse>("child still owns the namespace") { openStoreSession(store, ns) }
        holder.destroyForcibly()
        require(childStatus(holder) != 0, "holder died without closing")
    }
    val afterKill = openStoreSession(store, ns)
    require(afterKill.get(childKey).contentEquals("hold".encodeToByteArray()), "killed owner's durable write")
    afterKill.end()

    // This process's release fails: the namespace stays held for its owner, another process
    // included, until the release call confirms it.
    Watchdog.enter("$name: an unconfirmed release")
    val unconfirmed = openStoreSession(store, ns)
    store.failNextRelease.set(true)
    refused<StoreFailure.Unavailable>("unconfirmed release") { unconfirmed.end() }
    require(store.holds(ns), "an unconfirmed release frees nothing")
    withChild(root, ns, "busy") { require(childStatus(it) == busyStatus, "child saw the owed owner") }
    releaseOwedLocks(store)
    require(!store.holds(ns), "the release call confirmed the release")
    releaseOwedLocks(store)
    withChild(root, ns, "write") { require(childStatus(it) == 0, "child acquired after the release") }
}

private suspend fun test_store_records(root: Path, ns: String, store: FileStore) {
    val low = byteArrayOf(7, 0)
    val middle = byteArrayOf(7, 127)
    val high = byteArrayOf(7, -1)
    storeUnownedCommit(store, listOf(StoreWrite.Put(ns, low, low)))
    val session = openStoreSession(store, ns)
    for (key in listOf(high, middle, childKey)) session.put(key, key)
    val page = session.scan(byteArrayOf(7), null, 2u)
    require(page.size == 2 && page[0].key.contentEquals(low) && page[1].key.contentEquals(middle), "ordered page")
    val tail = session.scan(byteArrayOf(7), middle, 1u)
    require(tail.size == 1 && tail.single().key.contentEquals(high) && tail.single().value.contentEquals(high), "exclusive cursor")
    require(session.get(high).contentEquals(high), "record value")
    require(tail.single().toString() == "StoreEntry(<redacted>)", "scan entry description")
    val other = FileStore(root)
    refused<StoreFailure.InUse>("second local handle") { openStoreSession(other, ns) }
    val writes = listOf(StoreWrite.Put("other", low, high), StoreWrite.Delete(ns, low))
    require(writes.first().toString() == "StoreWrite(<redacted>)", "write description")
    refused<StoreFailure.InUse>("whole raw batch") { storeUnownedCommit(other, writes) }
    val untouched = openStoreSession(other, "other")
    require(untouched.get(low) == null && session.get(low).contentEquals(low), "no partial raw write")
    untouched.end()
    session.deletePrefix(byteArrayOf(7))
    require(session.scan(byteArrayOf(7), null, 4u).isEmpty() && session.get(childKey).contentEquals(childKey), "prefix deletion")
    session.end()
    storeUnownedCommit(store, listOf(StoreWrite.Delete(ns, childKey)))
    val deleted = openStoreSession(store, ns)
    require(deleted.get(childKey) == null, "exact deletion")
    deleted.end()
}

private suspend fun test_store_commit_outcomes(ns: String, store: FileStore) {
    val stale = openStoreSession(store, ns)
    store.forget(ns)
    val current = openStoreSession(store, ns)
    val key = byteArrayOf(42)
    refused<StoreFailure.NotOwner>("stale commit") { stale.put(key, key) }
    refused<StoreFailure.NotOwner>("stale read") { stale.get(key) }
    require(current.get(key) == null, "stale commit changed nothing")
    refused<StoreFailure.NotOwner>("ending a stale session") { stale.end() }
    refused<StoreFailure.InUse>("stale release preserved current ownership") { openStoreSession(store, ns) }
    store.unknownAfterWrite.set(true)
    refused<StoreFailure.Unknown>("ambiguous commit") { current.put(key, key) }
    require(current.get(key).contentEquals(key), "unknown commit was applied")
    current.end()
}

// A store callback that throws an `Error`, not an `Exception`, is read as a failure: never
// as a commit applied or an owner released, also when the host's own handler for it throws.
private suspend fun test_store_callback_errors(ns: String, store: FileStore) {
    val jnaHandler = Native.getCallbackExceptionHandler()
    val reported = CopyOnWriteArrayList<Throwable>()
    try {
        for (handlerThrows in listOf(false, true)) {
            Native.setCallbackExceptionHandler { _, thrown ->
                reported.add(thrown)
                if (handlerThrows) throw IllegalStateException("the handler failed")
            }
            val key = byteArrayOf(if (handlerThrows) 61 else 60)
            val session = openStoreSession(store, ns)
            store.errorOn.set("commitIf")
            refused<StoreFailure.Unknown>("an Error from commitIf") { session.put(key, key) }
            require(session.get(key) == null, "an Error from commitIf committed nothing")
            store.errorOn.set("release")
            refused<StoreFailure.Unknown>("an Error from release") { session.end() }
            require(store.holds(ns), "an Error from release released nothing")
            session.end()
            require(!store.holds(ns), "ending again released the owner")
        }
        // Each Error thrown reaches the host's handler; a handler that throws is handed
        // its own failure too, which this leaves out.
        require(reported.count { it is AssertionError } == 4, "each Error reported to the host")
    } finally {
        Native.setCallbackExceptionHandler(jnaHandler)
    }
}

/** Check ordered records, durable commits and exclusive ownership (Dispatch spec 3.1). */
suspend fun checkStore() {
    val root = Files.createTempDirectory("signer-store")
    try {
        val store = FileStore(root)
        val ns = "signer/test"
        step("test_store_records") { test_store_records(root, ns, store) }
        step("test_store_process_ownership") { test_store_process_ownership(root, ns, store) }
        step("test_store_commit_outcomes") { test_store_commit_outcomes(ns, store) }
        step("test_store_callback_errors") { test_store_callback_errors(ns, store) }
    } finally {
        root.toFile().deleteRecursively()
    }
}
