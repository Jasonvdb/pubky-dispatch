"""Tests of prepare-bindings.py's guard on host callbacks: it replaces the block of every
wrapper the generator emits, and refuses generated text it doesn't recognise instead of
leaving a callback unguarded.

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

SYNC = ["uniffiTraitInterfaceCall", "uniffiTraitInterfaceCallWithError"]
ASYNC = ["uniffiTraitInterfaceCallAsync", "uniffiTraitInterfaceCallAsyncWithError"]
FIXED = f'FfiConverterString.lower("{prepare.CALLBACK_FAILURE}")'
KOTLIN_CALL = "            uniffiTraitInterfaceCallWithError(\n"
SWIFT_CALL = "            uniffiTraitInterfaceCallWithError(\n"
# One callback entry calling a synchronous wrapper, and one calling an asynchronous one.
KOTLIN_ENTRIES = {
    False: """\
internal object uniffiCallbackInterfaceHost {
    internal object `load`: UniffiCallbackInterfaceHostMethod0 {
        override fun callback(`uniffiHandle`: Long,) {
            uniffiTraitInterfaceCallWithError(
                uniffiCallStatus,
            )
        }
    }
}
""",
    True: """\
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
""",
}
SWIFT_ENTRIES = {
    False: """\
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
""",
    True: """\
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
""",
}


def declared(names, blocks, wrappers, shells, entries):
    """Source declaring the wrappers `names` as the generator shapes them, each around its
    generated block or the one `blocks` gives for it, and an entry calling each kind."""
    source = ""
    for name in names:
        head, tail = shells[name]
        source += head + (blocks or {}).get(name, wrappers[name][0]) + tail + "\n"
    return source + "".join(entries[kind] for kind in sorted({"Async" in name for name in names}))


def kotlin(names, blocks=None):
    return declared(names, blocks, prepare.KOTLIN_WRAPPERS, prepare.KOTLIN_SHELLS, KOTLIN_ENTRIES)


def swift(names, blocks=None):
    return declared(names, blocks, prepare.SWIFT_WRAPPERS, prepare.SWIFT_SHELLS, SWIFT_ENTRIES)


class GuardCallbacks(unittest.TestCase):
    def test_guard_replaces_every_wrapper(self):
        for names in [SYNC, SYNC + ASYNC]:
            guarded_kotlin, guarded_swift = prepare.guard_callbacks(kotlin(names), swift(names))
            wrappers = len(names)
            self.assertEqual(guarded_kotlin.count("} catch(e: kotlin.Throwable) {"), wrappers)
            self.assertNotIn("catch(e: kotlin.Exception)", guarded_kotlin)
            self.assertNotIn("toString", guarded_kotlin)
            self.assertEqual(guarded_kotlin.count(FIXED), wrappers)
            # A typed failure is lowered once, guarded, before anything is reported.
            self.assertEqual(guarded_kotlin.count("lowerError(e)"), wrappers // 2)
            self.assertEqual(guarded_kotlin.count("try { lowerError(e) } catch("), wrappers // 2)
            # What isn't an Exception is thrown on once reported: a synchronous wrapper
            # writes the status itself first and lets a cancellation be; an asynchronous
            # one has completed by then, and throws a cancellation on too.
            self.assertEqual(guarded_kotlin.count(
                "if (e !is kotlin.Exception) {\n            callStatus.write()\n            throw e\n"), 1)
            self.assertEqual(guarded_kotlin.count(
                "if (e !is kotlin.Exception) {\n                callStatus.write()\n                throw e\n"), 1)
            self.assertEqual(guarded_kotlin.count("throw e"), wrappers)
            self.assertEqual(guarded_kotlin.count(
                "CancellationException) throw e\n            return@coroutineBlock\n"), wrappers - 2)
            self.assertNotIn("describing", guarded_swift)
            self.assertNotIn("catch let error {", guarded_swift)
            self.assertEqual(guarded_swift.count(FIXED), wrappers)
            for source, guarded in [(kotlin(names), guarded_kotlin), (swift(names), guarded_swift)]:
                # Nothing outside the wrappers' blocks changes.
                self.assertEqual(source.split("\ninternal object uniffiCallback")[1:],
                                 guarded.split("\ninternal object uniffiCallback")[1:])

    def test_guard_accepts_bindings_without_callbacks(self):
        self.assertEqual(prepare.guard_callbacks("fun plain() {}\n", "func plain() {}\n"),
                         ("fun plain() {}\n", "func plain() {}\n"))
        # A doc comment may name what the guard replaces in a handler.
        prepare.guard_callbacks(kotlin(SYNC) + "// value.toString() and catch (e: Exception)\n",
                                swift(SYNC) + "// String(describing: error)\n")

    def refused(self, kotlin_source, swift_source, why):
        with self.assertRaises(ValueError) as refusal:
            prepare.guard_callbacks(kotlin_source, swift_source)
        self.assertIn(why, str(refusal.exception))

    def test_guard_refuses_a_wrapper_shaped_otherwise(self):
        """Each change to a wrapper's block is refused, one test case per change."""
        changes = {
            "Kotlin": {
                # The host's method called outside the guarded block.
                SYNC[0]: [("    try {\n        writeReturn(makeCall())\n",
                           "    val made = makeCall()\n    try {\n        writeReturn(made)\n"),
                          # No failure reported.
                          ("        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR\n", ""),
                          ("kotlin.Exception", "kotlin.RuntimeException"),
                          ("e.toString()", "e.message")],
                SYNC[1]: [("    try {\n        writeReturn(makeCall())\n",
                           "    val made = makeCall()\n    try {\n        writeReturn(made)\n"),
                          ("            callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR\n", ""),
                          ("            callStatus.code = UNIFFI_CALL_ERROR\n", ""),
                          ("if (e is E) {", "if (E::class.isInstance(e)) {"),
                          ("= lowerError(e)", "= lowerError(e as E)")],
                ASYNC[0]: [("        val callResult = try {\n            makeCall()\n",
                            "        val made = makeCall()\n        val callResult = try {\n            made\n"),
                           # The failure built, and never sent.
                           ("            handleError(\n", "            listOf(\n"),
                           ("                    UNIFFI_CALL_UNEXPECTED_ERROR,\n", ""),
                           ("        handleSuccess(callResult)\n", ""),
                           ("            return@coroutineBlock\n", "")],
                ASYNC[1]: [("        val callResult = try {\n            makeCall()\n",
                            "        val made = makeCall()\n        val callResult = try {\n            made\n"),
                           ("            } else {\n                handleError(\n",
                            "            } else {\n                listOf(\n"),
                           ("            if (e is E) {\n                handleError(\n",
                            "            if (e is E) {\n                listOf(\n"),
                           ("                        UNIFFI_CALL_UNEXPECTED_ERROR,\n", ""),
                           ("                        UNIFFI_CALL_ERROR,\n", ""),
                           ("        handleSuccess(callResult)\n", "")],
            },
            "Swift": {
                SYNC[0]: [("    do {\n        try writeReturn(makeCall())\n",
                           "    let made = try? makeCall()\n    do {\n        try writeReturn(made!)\n"),
                          ("CALL_UNEXPECTED_ERROR", "CALL_SUCCESS"),
                          ("String(describing: error)", '"\\(error)"')],
                SYNC[1]: [("    do {\n        try writeReturn(makeCall())\n",
                           "    let made = try? makeCall()\n    do {\n        try writeReturn(made!)\n"),
                          ("CALL_UNEXPECTED_ERROR", "CALL_SUCCESS"),
                          ("code = CALL_ERROR", "code = CALL_SUCCESS")],
                ASYNC[0]: [("handleError(CALL_UNEXPECTED_ERROR, ", "print(CALL_UNEXPECTED_ERROR, "),
                           ("        handleSuccess(callResult)\n", "")],
                ASYNC[1]: [("handleError(CALL_UNEXPECTED_ERROR, ", "print(CALL_UNEXPECTED_ERROR, "),
                           ("handleError(CALL_ERROR, ", "print(CALL_ERROR, "),
                           ("        handleSuccess(callResult)\n", "")],
            },
        }
        names = SYNC + ASYNC
        cases = 0
        for language, wrappers, build in [("Kotlin", prepare.KOTLIN_WRAPPERS, kotlin),
                                          ("Swift", prepare.SWIFT_WRAPPERS, swift)]:
            for name in names:
                generated = wrappers[name][0]
                for old, new in changes[language][name]:
                    with self.subTest(language=language, wrapper=name, change=old):
                        self.assertEqual(generated.count(old), 1)
                        changed = build(names, {name: generated.replace(old, new)})
                        sources = (changed, swift(names)) if language == "Kotlin" else (kotlin(names), changed)
                        self.refused(*sources, f"{language}: {name} isn't the callback wrapper expected")
                        cases += 1
        self.assertEqual(cases, 31)

    def test_guard_refuses_a_host_call_outside_the_block(self):
        """The block unchanged, and the host's method also called before or after it."""
        names = SYNC + ASYNC
        for language, wrappers, build in [("Kotlin", prepare.KOTLIN_WRAPPERS, kotlin),
                                          ("Swift", prepare.SWIFT_WRAPPERS, swift)]:
            for name in names:
                generated = wrappers[name][0]
                indent = generated[:len(generated) - len(generated.lstrip(" "))]
                call = f"{indent}makeCall()\n" if language == "Kotlin" else f"{indent}_ = try? makeCall()\n"
                for changed in [call + generated, generated + call]:
                    with self.subTest(language=language, wrapper=name, first=changed[:40]):
                        source = build(names, {name: changed})
                        sources = (source, swift(names)) if language == "Kotlin" else (kotlin(names), source)
                        self.refused(*sources, f"{language}: {name} isn't the callback wrapper expected")

    def test_guard_accepts_a_wrapper_with_other_comments(self):
        commented = kotlin(SYNC).replace("    try {\n", "    // A comment of the generator's.\n    try {\n", 1)
        guarded, _ = prepare.guard_callbacks(commented, swift(SYNC))
        self.assertIn("// A comment of the generator's.", guarded)
        self.assertEqual(guarded.count("} catch(e: kotlin.Throwable) {"), 2)

    def test_guard_refuses_a_block_generated_twice(self):
        twice = prepare.KOTLIN_WRAPPERS[SYNC[0]][0] * 2
        self.refused(kotlin(SYNC, {SYNC[0]: twice}), swift(SYNC), "isn't the callback wrapper expected")

    def test_guard_refuses_a_wrapper_it_does_not_know(self):
        expected = "a callback wrapper isn't guarded"
        unknown = "            uniffiTraitInterfaceCallBlocking(\n"
        self.refused(kotlin(SYNC).replace(KOTLIN_CALL, unknown), swift(SYNC), expected)
        self.refused(kotlin(SYNC), swift(SYNC).replace(SWIFT_CALL, unknown), expected)

    def test_guard_refuses_a_callback_called_past_the_wrappers(self):
        expected = "isn't called through a guarded wrapper"
        direct = "            writeReturn(makeCall())\n"
        self.refused(kotlin(SYNC).replace(KOTLIN_CALL, direct), swift(SYNC), expected)
        self.refused(kotlin(SYNC), swift(SYNC).replace(SWIFT_CALL, direct), expected)

    def test_guard_refuses_a_callback_method_without_a_failure(self):
        expected = "a host callback method declares no failure"
        plain = "            uniffiTraitInterfaceCall(\n"
        self.refused(kotlin(SYNC).replace(KOTLIN_CALL, plain), swift(SYNC), expected)
        self.refused(kotlin(SYNC), swift(SYNC).replace(SWIFT_CALL, plain), expected)

    def test_guard_refuses_another_handler_left_unguarded(self):
        self.refused(kotlin(SYNC) + "    } catch (e: Exception) {\n", swift(SYNC),
                     "catches Exception only")
        self.refused(kotlin(SYNC) + "    FfiConverterString.lower(e.toString())\n", swift(SYNC),
                     "Kotlin: a generated handler describes what was thrown")
        self.refused(kotlin(SYNC), swift(SYNC) + "    FfiConverterString.lower(String(describing: error))\n",
                     "Swift: a generated handler describes what was thrown")

    def test_script_exits_with_a_failure(self):
        generated = prepare.KOTLIN_WRAPPERS[SYNC[0]][0]
        changed = kotlin(SYNC, {SYNC[0]: generated.replace("kotlin.Exception", "kotlin.RuntimeException")})
        with tempfile.TemporaryDirectory() as directory:
            kotlin_path = Path(directory) / "bindings.kt"
            swift_path = Path(directory) / "bindings.swift"
            kotlin_path.write_text("getByteBuffer(0, this.len.toLong())\n" + changed)
            swift_path.write_text(swift(SYNC))
            ran = subprocess.run(
                [sys.executable, str(SCRIPT), str(kotlin_path), str(swift_path),
                 str(Path(directory) / "redaction.swift")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(ran.returncode, 0)
            self.assertIn("uniffiTraitInterfaceCall isn't the callback wrapper expected", ran.stderr)
            self.assertEqual(swift_path.read_text(), swift(SYNC))


class CheckObjects(unittest.TestCase):
    LISTED = "open class HostSecret: Disposable, AutoCloseable, HostSecretInterface\n"

    def refused(self, kotlin_source, why):
        with self.assertRaises(ValueError) as refusal:
            prepare.check_objects(kotlin_source)
        self.assertIn(why, str(refusal.exception))

    def test_objects_listed_are_accepted(self):
        # Every listed object, some of them, or none: a build needn't export each one.
        prepare.check_objects("")
        prepare.check_objects(self.LISTED)
        prepare.check_objects("".join(f"open class {name}: Disposable\n" for name in sorted(prepare.OPAQUE)))

    def test_objects_accept_the_store_session(self):
        # The store fixtures' session: a fixture build exports it.
        prepare.check_objects(self.LISTED + "open class StoreSession: Disposable, AutoCloseable, StoreSessionInterface\n")

    def test_objects_refuse_an_unlisted_object(self):
        self.refused(self.LISTED + "open class Unlisted: Disposable, AutoCloseable, UnlistedInterface\n",
                     "exported objects not listed as opaque: ['Unlisted']")

    def test_objects_refuse_an_object_passed_as_an_argument(self):
        self.refused(self.LISTED + "    FfiConverterTypeHostSecret.lower(`secret`),\n",
                     "HostSecret is passed as an argument")

    def test_objects_refuse_an_object_described_as_a_value(self):
        self.refused("data class HostSecret (\n", "HostSecret is generated as a described value")

    def test_objects_refuse_an_unlisted_object_that_is_an_error(self):
        self.refused("open class Unlisted : kotlin.Exception, Disposable, AutoCloseable, UnlistedInterface\n",
                     "exported objects not listed as opaque: ['Unlisted']")

    # A record that holds an option of a handle, then that option, as the generator
    # writes their converters.
    HELD = """\
public object FfiConverterTypeHolder: FfiConverterRustBuffer<Holder> {
    override fun write(value: Holder, buf: ByteBuffer) {
            FfiConverterOptionalTypeHostSecret.write(value.`secret`, buf)
    }
}

public object FfiConverterOptionalTypeHostSecret: FfiConverterRustBuffer<HostSecret?> {
    override fun read(buf: ByteBuffer): HostSecret? {
        return FfiConverterTypeHostSecret.read(buf)
    }

    override fun write(value: HostSecret?, buf: ByteBuffer) {
        FfiConverterTypeHostSecret.write(value, buf)
    }
}
"""

    def test_objects_accept_an_object_that_comes_back_inside_a_value(self):
        prepare.check_objects(self.LISTED + self.HELD
                              + "    return FfiConverterOptionalTypeHostSecret.lift(result)\n"
                              + "    return FfiConverterTypeHolder.lift(result)\n")

    def test_objects_refuse_an_object_passed_inside_an_option(self):
        self.refused(self.LISTED + self.HELD + "    FfiConverterOptionalTypeHostSecret.lower(`secret`),\n",
                     "an opaque object is passed inside a value: FfiConverterOptionalTypeHostSecret")

    def test_objects_refuse_an_object_passed_inside_a_record(self):
        self.refused(self.LISTED + self.HELD + "    FfiConverterTypeHolder.lower(`holder`),\n",
                     "an opaque object is passed inside a value: FfiConverterTypeHolder")


if __name__ == "__main__":
    unittest.main()
