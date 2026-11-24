"""Tests of prepare-bindings.py's guard on host callbacks: it rewrites every wrapper the
generator emits, and refuses generated text it doesn't recognise instead of leaving a
callback unguarded.

Run with: python3 tests/prepare_bindings_test.py
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent.parent / "prepare-bindings.py"
spec = importlib.util.spec_from_file_location("prepare_bindings", SCRIPT)
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

# The wrappers as UniFFI generates them, and one callback entry calling each kind.
KOTLIN_SYNC = """
internal inline fun<T> uniffiTraitInterfaceCall(
    callStatus: UniffiRustCallStatus,
) {
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Exception) {
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        callStatus.error_buf = FfiConverterString.lower(e.toString())
    }
}

internal inline fun<T, reified E: Throwable> uniffiTraitInterfaceCallWithError(
    callStatus: UniffiRustCallStatus,
) {
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Exception) {
        if (e is E) {
            callStatus.code = UNIFFI_CALL_ERROR
            callStatus.error_buf = lowerError(e)
        } else {
            callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
            callStatus.error_buf = FfiConverterString.lower(e.toString())
        }
    }
}

internal object uniffiCallbackInterfaceHost {
    internal object `load`: UniffiCallbackInterfaceHostMethod0 {
        override fun callback(`uniffiHandle`: Long,) {
            uniffiTraitInterfaceCallWithError(
                uniffiCallStatus,
            )
        }
    }
}
"""
KOTLIN_ASYNC = """
internal inline fun<T> uniffiTraitInterfaceCallAsync(
    crossinline makeCall: suspend () -> T,
): UniffiForeignFuture {
    val job = GlobalScope.launch coroutineBlock@ {
        val callResult = try {
            makeCall()
        } catch(e: kotlin.Exception) {
            handleError(
                UniffiRustCallStatus.create(
                    UNIFFI_CALL_UNEXPECTED_ERROR,
                    FfiConverterString.lower(e.toString()),
                )
            )
            return@coroutineBlock
        }
        handleSuccess(callResult)
    }
}

internal inline fun<T, reified E: Throwable> uniffiTraitInterfaceCallAsyncWithError(
    crossinline makeCall: suspend () -> T,
): UniffiForeignFuture {
    val job = GlobalScope.launch coroutineBlock@ {
        val callResult = try {
            makeCall()
        } catch(e: kotlin.Exception) {
            if (e is E) {
                handleError(
                    UniffiRustCallStatus.create(
                        UNIFFI_CALL_ERROR,
                        lowerError(e),
                    )
                )
            } else {
                handleError(
                    UniffiRustCallStatus.create(
                        UNIFFI_CALL_UNEXPECTED_ERROR,
                        FfiConverterString.lower(e.toString()),
                    )
                )
            }
            return@coroutineBlock
        }
        handleSuccess(callResult)
    }
}

internal object uniffiCallbackInterfaceHostAsync {
    internal object `get`: UniffiCallbackInterfaceHostAsyncMethod0 {
        override fun callback(`uniffiHandle`: Long,) {
            uniffiOutReturn.uniffiSetValue(
                uniffiTraitInterfaceCallAsyncWithError(
                    makeCall,
                )
            )
        }
    }
}
"""
SWIFT_SYNC = """
private func uniffiTraitInterfaceCall<T>(
    callStatus: UnsafeMutablePointer<RustCallStatus>
) {
    do {
        try writeReturn(makeCall())
    } catch let error {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
}

private func uniffiTraitInterfaceCallWithError<T, E>(
    callStatus: UnsafeMutablePointer<RustCallStatus>
) {
    do {
        try writeReturn(makeCall())
    } catch let error as E {
        callStatus.pointee.code = CALL_ERROR
        callStatus.pointee.errorBuf = lowerError(error)
    } catch {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
}

fileprivate struct UniffiCallbackInterfaceHost {
        load: { (
            uniffiHandle: UInt64,
            uniffiCallStatus: UnsafeMutablePointer<RustCallStatus>
        ) in
            uniffiTraitInterfaceCallWithError(
                callStatus: uniffiCallStatus
            )
        },
        uniffiFree: { (uniffiHandle: UInt64) -> () in
        }
}
"""
SWIFT_ASYNC = """
private func uniffiTraitInterfaceCallAsync<T>(
    makeCall: @escaping () async throws -> T
) -> UniffiForeignFuture {
    let task = Task {
        do {
            callResult = try await makeCall()
        } catch {
            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower(String(describing: error)))
            return
        }
    }
}

private func uniffiTraitInterfaceCallAsyncWithError<T, E>(
    makeCall: @escaping () async throws -> T
) -> UniffiForeignFuture {
    let task = Task {
        do {
            callResult = try await makeCall()
        } catch let error as E {
            handleError(CALL_ERROR, lowerError(error))
        } catch {
            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower(String(describing: error)))
        }
    }
}

fileprivate struct UniffiCallbackInterfaceHostAsync {
        get: { (
            uniffiHandle: UInt64,
            uniffiOutReturn: UnsafeMutablePointer<UniffiForeignFuture>
        ) in
            let uniffiForeignFuture = uniffiTraitInterfaceCallAsyncWithError(
                makeCall: makeCall
            )
        },
}
"""
FIXED = f'FfiConverterString.lower("{prepare.CALLBACK_FAILURE}")'
KOTLIN_CALL = "            uniffiTraitInterfaceCallWithError(\n"
SWIFT_CALL = "            uniffiTraitInterfaceCallWithError(\n"


class GuardCallbacks(unittest.TestCase):
    def test_guard_rewrites_every_wrapper(self):
        for kotlin, swift, wrappers in [
            (KOTLIN_SYNC, SWIFT_SYNC, 2),
            (KOTLIN_SYNC + KOTLIN_ASYNC, SWIFT_SYNC + SWIFT_ASYNC, 4),
        ]:
            guarded_kotlin, guarded_swift = prepare.guard_callbacks(kotlin, swift)
            self.assertEqual(guarded_kotlin.count("} catch(e: kotlin.Throwable) {"), wrappers)
            self.assertNotIn("catch(e: kotlin.Exception)", guarded_kotlin)
            # Reported, then thrown on: after the status in a synchronous wrapper, and
            # after either completion in an asynchronous one.
            self.assertEqual(guarded_kotlin.count(
                f"{FIXED}\n        if (e !is kotlin.Exception) throw e\n    }}\n"), 1)
            self.assertEqual(guarded_kotlin.count(
                f"{FIXED}\n            if (e !is kotlin.Exception) throw e\n        }}\n"), 1)
            self.assertEqual(guarded_kotlin.count(
                "CancellationException) throw e\n            return@coroutineBlock\n"),
                wrappers - 2)
            self.assertNotIn("toString", guarded_kotlin)
            self.assertEqual(guarded_kotlin.count(FIXED), wrappers)
            # A typed failure is lowered once, guarded, before anything is reported.
            self.assertEqual(guarded_kotlin.count("lowerError(e)"), wrappers // 2)
            self.assertEqual(guarded_kotlin.count("try { lowerError(e) } catch("), wrappers // 2)
            self.assertEqual(guarded_kotlin.count("if (lowered != null) {"), wrappers // 2)
            self.assertNotIn("describing", guarded_swift)
            self.assertNotIn("catch let error {", guarded_swift)
            self.assertEqual(guarded_swift.count(FIXED), wrappers)

    def test_guard_accepts_bindings_without_callbacks(self):
        self.assertEqual(prepare.guard_callbacks("fun plain() {}\n", "func plain() {}\n"),
                         ("fun plain() {}\n", "func plain() {}\n"))
        # A doc comment may name what the guard replaces in a handler.
        kotlin = KOTLIN_SYNC + "// value.toString() and catch (e: Exception)\n"
        swift = SWIFT_SYNC + "// String(describing: error)\n"
        prepare.guard_callbacks(kotlin, swift)

    def refused(self, kotlin, swift, why):
        with self.assertRaises(ValueError) as refusal:
            prepare.guard_callbacks(kotlin, swift)
        self.assertIn(why, str(refusal.exception))

    def test_guard_refuses_a_wrapper_that_catches_otherwise(self):
        expected = "isn't the callback wrapper expected"
        self.refused(KOTLIN_SYNC.replace("kotlin.Exception", "kotlin.RuntimeException", 1),
                     SWIFT_SYNC, expected)
        twice = KOTLIN_SYNC.replace("        writeReturn(makeCall())\n",
                                    "    } catch(e: kotlin.Exception) {\n", 1)
        self.refused(twice, SWIFT_SYNC, expected)

    def test_guard_refuses_a_wrapper_that_describes_otherwise(self):
        expected = "isn't the callback wrapper expected"
        self.refused(KOTLIN_SYNC.replace("e.toString()", "e.message", 1), SWIFT_SYNC, expected)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC.replace("String(describing: error)", '"\\(error)"', 1),
                     expected)

    def test_guard_refuses_a_wrapper_that_reports_no_status(self):
        expected = "isn't the callback wrapper expected"
        both = (KOTLIN_SYNC + KOTLIN_ASYNC, SWIFT_SYNC + SWIFT_ASYNC)
        # Each status a Kotlin wrapper reports, after the line that leads to it.
        for before, status in [
            ("    } catch(e: kotlin.Exception) {\n", "        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR\n"),
            ("        } else {\n", "            callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR\n"),
            ("        if (e is E) {\n", "            callStatus.code = UNIFFI_CALL_ERROR\n"),
            ("                UniffiRustCallStatus.create(\n", "                    UNIFFI_CALL_UNEXPECTED_ERROR,\n"),
            ("                    UniffiRustCallStatus.create(\n", "                        UNIFFI_CALL_UNEXPECTED_ERROR,\n"),
            ("                    UniffiRustCallStatus.create(\n", "                        UNIFFI_CALL_ERROR,\n"),
        ]:
            self.assertEqual(both[0].count(before + status), 1, status)
            self.refused(both[0].replace(before + status, before), both[1], expected)
        # Each unexpected status a Swift wrapper reports, in its own surroundings.
        for status in [
            "    } catch let error {\n        callStatus.pointee.code = CALL_UNEXPECTED_ERROR\n",
            "    } catch {\n        callStatus.pointee.code = CALL_UNEXPECTED_ERROR\n",
            "            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower(String(describing: error)))\n            return\n",
            "            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower(String(describing: error)))\n        }\n",
        ]:
            self.assertEqual(both[1].count(status), 1, status)
            unreported = status.replace("CALL_UNEXPECTED_ERROR", "CALL_SUCCESS")
            self.refused(both[0], both[1].replace(status, unreported), expected)

    def test_guard_refuses_a_wrapper_that_lowers_otherwise(self):
        expected = "isn't the callback wrapper expected"
        self.refused(KOTLIN_SYNC.replace("if (e is E) {", "if (E::class.isInstance(e)) {"),
                     SWIFT_SYNC, expected)
        self.refused(KOTLIN_SYNC.replace("= lowerError(e)", "= lowerError(e as E)"),
                     SWIFT_SYNC, expected)

    def test_guard_refuses_a_wrapper_it_does_not_know(self):
        expected = "a callback wrapper isn't guarded"
        unknown = "            uniffiTraitInterfaceCallBlocking(\n"
        self.refused(KOTLIN_SYNC.replace(KOTLIN_CALL, unknown), SWIFT_SYNC, expected)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC.replace(SWIFT_CALL, unknown), expected)

    def test_guard_refuses_a_callback_called_past_the_wrappers(self):
        expected = "isn't called through a guarded wrapper"
        direct = "            writeReturn(makeCall())\n"
        self.refused(KOTLIN_SYNC.replace(KOTLIN_CALL, direct), SWIFT_SYNC, expected)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC.replace(SWIFT_CALL, direct), expected)

    def test_guard_refuses_a_callback_method_without_a_failure(self):
        expected = "a host callback method declares no failure"
        plain = "            uniffiTraitInterfaceCall(\n"
        self.refused(KOTLIN_SYNC.replace(KOTLIN_CALL, plain), SWIFT_SYNC, expected)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC.replace(SWIFT_CALL, plain), expected)

    def test_guard_refuses_another_handler_left_unguarded(self):
        self.refused(KOTLIN_SYNC + "    } catch (e: Exception) {\n", SWIFT_SYNC,
                     "catches Exception only")
        self.refused(KOTLIN_SYNC + "    FfiConverterString.lower(e.toString())\n", SWIFT_SYNC,
                     "Kotlin: a generated handler describes what was thrown")
        self.refused(KOTLIN_SYNC, SWIFT_SYNC + "    FfiConverterString.lower(String(describing: error))\n",
                     "Swift: a generated handler describes what was thrown")

    def test_script_exits_with_a_failure(self):
        changed = KOTLIN_SYNC.replace("kotlin.Exception", "kotlin.RuntimeException", 1)
        with tempfile.TemporaryDirectory() as directory:
            kotlin = Path(directory) / "bindings.kt"
            swift = Path(directory) / "bindings.swift"
            kotlin.write_text("getByteBuffer(0, this.len.toLong())\n" + changed)
            swift.write_text(SWIFT_SYNC)
            ran = subprocess.run(
                [sys.executable, str(SCRIPT), str(kotlin), str(swift),
                 str(Path(directory) / "redaction.swift")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(ran.returncode, 0)
            self.assertIn("uniffiTraitInterfaceCall isn't the callback wrapper expected", ran.stderr)
            self.assertEqual(swift.read_text(), SWIFT_SYNC)


if __name__ == "__main__":
    unittest.main()
