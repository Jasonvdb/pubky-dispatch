// The Kotlin host's checks of the host store adapter.
package pubky.dispatch.signer.tests

/** Check the host store adapter. */
suspend fun checkStore() {
}

/**
 * Run as the second process of a two-process store check when `args` ask for it. Returns
 * whether it did, in which case the host program does nothing else.
 */
suspend fun storeHostChild(args: List<String>): Boolean = false
