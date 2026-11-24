// The host's durable store checks (Switch spec 3.1).
package pubky.switch.signer.tests

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
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.system.exitProcess
import pubky.switch.signer.HostStore
import pubky.switch.signer.StoreAcquire
import pubky.switch.signer.StoreCommit
import pubky.switch.signer.StoreEntry
import pubky.switch.signer.StoreFailure
import pubky.switch.signer.StoreWrite
import pubky.switch.signer.storeProbe
import pubky.switch.signer.storeUnownedPut

private val hex = HexFormat.of()
private const val valueCap = 16L shl 20
private const val batchCap = 32L shl 20

private val StoreWrite.namespace: String get() = when (this) {
    is StoreWrite.Put -> ns
    is StoreWrite.Delete -> ns
    is StoreWrite.DeletePrefix -> ns
}

private fun checkBatch(writes: List<StoreWrite>, ns: String? = null) {
    var size = ns?.let { it.encodeToByteArray().size.toLong() + 32L } ?: 0L
    for (write in writes) {
        if (ns != null && ns != write.namespace) throw StoreFailure.Other()
        size += write.namespace.encodeToByteArray().size
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
private class FileStore(directory: Path) : HostStore {
    private val root = directory.toRealPath()
    private val records = root.resolve("records")
    val unknownAfterWrite = AtomicBoolean()

    companion object {
        // POSIX record locks belong to the JVM. Even closing a second channel for the
        // same inode can release its lock. Consult this table before opening that file.
        private val owners = mutableMapOf<Path, HeldLock>()
    }

    private fun <T> transaction(body: () -> T): T = synchronized(owners) {
        try {
            FileChannel.open(root.resolve("transaction.lock"), CREATE, WRITE).use { file ->
                file.lock().use { body() }
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

    override fun acquire(ns: String, owner: ByteArray): StoreAcquire = transaction {
        checkOwner(owner)
        val path = lockPath(ns)
        val lock = tryLock(path) ?: return@transaction StoreAcquire.BUSY
        owners[path] = HeldLock(owner.copyOf(), lock)
        StoreAcquire.ACQUIRED
    }

    override fun release(ns: String, owner: ByteArray): Unit = transaction {
        checkOwner(owner)
        val path = lockPath(ns)
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

    override fun get(ns: String, key: ByteArray): ByteArray? = transaction {
        read().getProperty(keyName(ns, key))?.let(::decode)
    }

    override fun scan(ns: String, prefix: ByteArray, after: ByteArray?, limit: UInt): List<StoreEntry> =
        transaction {
            val snapshot = read()
            val start = keyName(ns, prefix)
            val cursor = after?.let { keyName(ns, it) }
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
                    keyName(write.ns, write.key), Base64.getEncoder().encodeToString(write.value)
                )
                is StoreWrite.Delete -> snapshot.remove(keyName(write.ns, write.key))
                is StoreWrite.DeletePrefix -> {
                    val prefix = keyName(write.ns, write.prefix)
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
        for (ns in writes.map { it.namespace }.distinct()) {
            val lock = tryLock(lockPath(ns)) ?: throw StoreFailure.InUse()
            lock.channel().close()
        }
        apply(writes)
    }

    override fun commitIf(ns: String, owner: ByteArray, writes: List<StoreWrite>): StoreCommit =
        transaction {
            checkOwner(owner)
            checkBatch(writes, ns)
            if (!owners[lockPath(ns)]?.owner.contentEquals(owner)) return@transaction StoreCommit.NOT_OWNER
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
        "-cp", System.getProperty("java.class.path"), "pubky.switch.signer.tests.MainKt",
        childMarker, root.toString(), ns, action,
    ).redirectError(ProcessBuilder.Redirect.INHERIT).start()
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

/** Handle the second process of a store check (Switch spec 3.1). */
suspend fun storeHostChild(args: List<String>): Boolean {
    if (args.firstOrNull() != childMarker) return false
    require(args.size == 4, "store child arguments")
    val (_, directory, ns, action) = args
    val root = Path.of(directory)
    val store = FileStore(root)
    if (action == "busy") {
        val probe = try {
            storeProbe(store, ns)
        } catch (_: StoreFailure.InUse) {
            exitProcess(busyStatus)
        }
        probe.closeStore()
        return true
    }
    require(action == "write" || action == "hold", "store child action")
    val probe = storeProbe(store, ns)
    probe.put(childKey, action.encodeToByteArray())
    if (action == "hold") {
        Files.createFile(root.resolve("ready"))
        // The parent holds stdin open until it kills us. EOF also frees an orphan.
        System.`in`.read()
    }
    probe.closeStore()
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
    val probe = storeProbe(store, ns)
    withChild(root, ns, "busy") { require(childStatus(it) == busyStatus, "child saw the owner") }
    probe.closeStore()
    refused<StoreFailure.NotOwner>("closed probe") { probe.get(childKey) }
    withChild(root, ns, "write") { require(childStatus(it) == 0, "child acquired after close") }
    val reopened = storeProbe(store, ns)
    require(reopened.get(childKey).contentEquals("write".encodeToByteArray()), "child's durable write")
    reopened.closeStore()

    withChild(root, ns, "hold") { holder ->
        val started = System.nanoTime()
        while (!Files.exists(root.resolve("ready"))) {
            require(holder.isAlive, "holder exited before committing")
            require(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(30), "holder timed out")
            Thread.sleep(20)
        }
        refused<StoreFailure.InUse>("child still owns the namespace") { storeProbe(store, ns) }
        holder.destroyForcibly()
        require(childStatus(holder) != 0, "holder died without closing")
    }
    val afterKill = storeProbe(store, ns)
    require(afterKill.get(childKey).contentEquals("hold".encodeToByteArray()), "killed owner's durable write")
    afterKill.closeStore()
}

private suspend fun test_store_records(root: Path, ns: String, store: FileStore) {
    val low = byteArrayOf(7, 0)
    val middle = byteArrayOf(7, 127)
    val high = byteArrayOf(7, -1)
    storeUnownedPut(store, ns, low, low)
    val probe = storeProbe(store, ns)
    for (key in listOf(high, middle, childKey)) probe.put(key, key)
    val page = probe.scan(byteArrayOf(7), null, 2u)
    require(page.size == 2 && page[0].key.contentEquals(low) && page[1].key.contentEquals(middle), "ordered page")
    val tail = probe.scan(byteArrayOf(7), middle, 1u)
    require(tail.size == 1 && tail.single().key.contentEquals(high) && tail.single().value.contentEquals(high), "exclusive cursor")
    require(probe.get(high).contentEquals(high), "record value")
    require(tail.single().toString() == "StoreEntry(<redacted>)", "scan entry description")
    val other = FileStore(root)
    refused<StoreFailure.InUse>("second local handle") { storeProbe(other, ns) }
    refused<StoreFailure.InUse>("raw write to an owned namespace") { storeUnownedPut(other, ns, low, high) }
    val writes = listOf(StoreWrite.Put("other", low, high), StoreWrite.Delete(ns, low))
    require(writes.first().toString() == "StoreWrite(<redacted>)", "write description")
    refused<StoreFailure.Other>("short owner refused") { other.release(ns, byteArrayOf(1)) }
    refused<StoreFailure.InUse>("whole raw batch") { other.commit(writes) }
    require(other.get("other", low) == null && probe.get(low).contentEquals(low), "no partial raw write")
    probe.deletePrefix(byteArrayOf(7))
    require(probe.scan(byteArrayOf(7), null, 4u).isEmpty() && probe.get(childKey).contentEquals(childKey), "prefix deletion")
    probe.closeStore()
    store.commit(listOf(StoreWrite.Delete(ns, childKey)))
    require(store.get(ns, childKey) == null, "exact deletion")
}

private suspend fun test_store_commit_outcomes(ns: String, store: FileStore) {
    val stale = storeProbe(store, ns)
    store.forget(ns)
    val current = storeProbe(store, ns)
    val key = byteArrayOf(42)
    refused<StoreFailure.NotOwner>("stale commit") { stale.put(key, key) }
    refused<StoreFailure.NotOwner>("stale read") { stale.get(key) }
    require(current.get(key) == null, "stale commit changed nothing")
    refused<StoreFailure.NotOwner>("closing a stale probe") { stale.closeStore() }
    refused<StoreFailure.InUse>("stale release preserved current ownership") { storeProbe(store, ns) }
    store.unknownAfterWrite.set(true)
    refused<StoreFailure.Unknown>("ambiguous commit") { current.put(key, key) }
    require(current.get(key).contentEquals(key), "unknown commit was applied")
    current.closeStore()
}

/** Check ordered records, durable commits and exclusive ownership (Switch spec 3.1). */
suspend fun checkStore() {
    val root = Files.createTempDirectory("signer-store")
    try {
        val store = FileStore(root)
        val ns = "signer/test"
        test_store_records(root, ns, store)
        test_store_process_ownership(root, ns, store)
        test_store_commit_outcomes(ns, store)
    } finally {
        root.toFile().deleteRecursively()
    }
}
