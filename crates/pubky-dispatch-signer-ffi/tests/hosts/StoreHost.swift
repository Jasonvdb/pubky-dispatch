// The Swift host's checks of the host store adapter.
import Foundation
import PubkyDispatchSigner

/// Check the host store adapter.
func checkStore() async {
}

/// Run as the second process of a two-process store check when `args` ask for it. Returns
/// whether it did, in which case the host program does nothing else.
func storeHostChild(_ args: [String]) async -> Bool {
    false
}
