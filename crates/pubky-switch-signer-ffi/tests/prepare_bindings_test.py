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
        } else {
            callStatus.error_buf = FfiConverterString.lower(e.toString())
        }
    }
}

internal interface UniffiCallbackInterfaceHostMethod0 : com.sun.jna.Callback {
}
            uniffiTraitInterfaceCallWithError(
"""
KOTLIN_ASYNC = """
internal inline fun<T> uniffiTraitInterfaceCallAsync(
    crossinline makeCall: suspend () -> T,
): UniffiForeignFuture {
    val job = GlobalScope.launch coroutineBlock@ {
        val callResult = try {
            makeCall()
        } catch(e: kotlin.Exception) {
            handleError(FfiConverterString.lower(e.toString()))
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
            handleError(FfiConverterString.lower(e.toString()))
            return@coroutineBlock
        }
        handleSuccess(callResult)
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
        callStatus.pointee.errorBuf = lowerError(error)
    } catch {
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
}

fileprivate struct UniffiCallbackInterfaceHost {
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
"""
FIXED = f'FfiConverterString.lower("{prepare.CALLBACK_FAILURE}")'


class GuardCallbacks(unittest.TestCase):
    def test_guard_rewrites_every_wrapper(self):
        for kotlin, swift, wrappers in [
            (KOTLIN_SYNC, SWIFT_SYNC, 2),
            (KOTLIN_SYNC + KOTLIN_ASYNC, SWIFT_SYNC + SWIFT_ASYNC, 4),
        ]:
            guarded_kotlin, guarded_swift = prepare.guard_callbacks(kotlin, swift)
            self.assertEqual(guarded_kotlin.count("} catch(e: kotlin.Throwable) {"), wrappers)
            self.assertNotIn("kotlin.Exception", guarded_kotlin)
            self.assertNotIn("toString", guarded_kotlin)
            self.assertEqual(guarded_kotlin.count(FIXED), wrappers)
            self.assertNotIn("describing", guarded_swift)
            self.assertNotIn("catch let error {", guarded_swift)
            self.assertEqual(guarded_swift.count(FIXED), wrappers)

    def test_guard_leaves_bindings_without_callbacks(self):
        self.assertEqual(prepare.guard_callbacks("fun plain() {}\n", "func plain() {}\n"),
                         ("fun plain() {}\n", "func plain() {}\n"))

    def refused(self, kotlin, swift):
        with self.assertRaises(ValueError):
            prepare.guard_callbacks(kotlin, swift)

    def test_guard_refuses_a_wrapper_that_catches_otherwise(self):
        self.refused(KOTLIN_SYNC.replace("kotlin.Exception", "kotlin.RuntimeException", 1),
                     SWIFT_SYNC)

    def test_guard_refuses_a_wrapper_that_describes_otherwise(self):
        self.refused(KOTLIN_SYNC.replace("e.toString()", "e.message", 1), SWIFT_SYNC)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC.replace("String(describing: error)", '"\\(error)"', 1))

    def test_guard_refuses_a_wrapper_it_does_not_know(self):
        self.refused(KOTLIN_SYNC + "            uniffiTraitInterfaceCallBlocking(\n", SWIFT_SYNC)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC + "    uniffiTraitInterfaceCallBlocking(\n")

    def test_guard_refuses_callbacks_without_a_wrapper(self):
        renamed = KOTLIN_SYNC.replace("uniffiTraitInterfaceCall", "uniffiCallbackCall")
        self.refused(renamed, SWIFT_SYNC)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC.replace("uniffiTraitInterfaceCall", "uniffiCallbackCall"))

    def test_guard_refuses_another_handler_left_unguarded(self):
        self.refused(KOTLIN_SYNC + "    } catch (e: Exception) {\n", SWIFT_SYNC)
        self.refused(KOTLIN_SYNC + "    lower(e.toString())\n", SWIFT_SYNC)
        self.refused(KOTLIN_SYNC, SWIFT_SYNC + "    lower(String(describing: error))\n")

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
