"""Protect the generated descriptions of binding values, and a host callback's failure.

UniFFI describes a record or an enum with fields field by field, in Kotlin's toString,
an exception's message and Swift's description and reflection. Every such value the
bindings generate is redacted unless it is on PUBLIC below, whose fields carry nothing a
host must keep private. A secret never crosses in such a value at all: it crosses into an
opaque handle (OPAQUE), which this script checks the generator kept opaque.

What a host callback's method throws is reported to Rust as a failure, and hands no text
of the host's to Rust (`guard_callbacks`, which says what that covers).
"""
from pathlib import Path
import re
import sys

# Values whose fields are public: an identity's public half, and the typed error with the
# measurements and service facts it carries, which name a failure's class, rule and numbers
# only. Text another app chose, such as the scopes of `UnownedScopes`, isn't here: its value
# is redacted, while the host still reads its fields.
PUBLIC = {"PublicIdentity", "SignerFfiException", "RefusalMeasurements", "ServiceDetail"}
# Every exported object: a handle a secret crosses into, or one that holds the host's own
# objects. Generated as objects, never described field by field, and used only through its
# own methods. A name a build doesn't export is fine here: an object only a fixture build
# exports is listed too.
OPAQUE = {"HostSecret", "Keyring", "SignerEnvironment"}
# What Rust is handed in place of the text of what a host callback threw.
CALLBACK_FAILURE = "a host callback failed"


# Each of UniFFI's four wrappers around a host callback, with the block that calls the
# host's method and handles what it throws: as UniFFI 0.29.5 generates it, and as it is
# guarded. The two synchronous forms come first, then the two an asynchronous callback is
# launched through. The forms named `WithError` serve a method that declares a failure; the
# others have nowhere to report one.
#
# In the guarded Kotlin: every `Throwable` is caught, a typed failure is lowered before
# anything is reported and one that can't be lowered is an unexpected failure, the
# description of what was thrown is a fixed text, and what isn't an `Exception` is thrown on
# once the failure is reported. A synchronous wrapper writes the status to native memory
# itself before it throws: JNA writes it back only after its exception handler returns,
# which a host's handler may not. A cancellation still cancels an asynchronous callback's
# coroutine. In the guarded Swift only the description changes.
KOTLIN_WRAPPERS = {
    "uniffiTraitInterfaceCall": ("""\
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Exception) {
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        callStatus.error_buf = FfiConverterString.lower(e.toString())
    }
""", """\
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Throwable) {
        callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
        callStatus.error_buf = FfiConverterString.lower("CALLBACK_FAILURE")
        if (e !is kotlin.Exception) {
            callStatus.write()
            throw e
        }
    }
"""),
    "uniffiTraitInterfaceCallWithError": ("""\
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
""", """\
    try {
        writeReturn(makeCall())
    } catch(e: kotlin.Throwable) {
        val lowered = if (e is E) try { lowerError(e) } catch(unlowered: kotlin.Throwable) { null } else null
        if (lowered != null) {
            callStatus.code = UNIFFI_CALL_ERROR
            callStatus.error_buf = lowered
        } else {
            callStatus.code = UNIFFI_CALL_UNEXPECTED_ERROR
            callStatus.error_buf = FfiConverterString.lower("CALLBACK_FAILURE")
            if (e !is kotlin.Exception) {
                callStatus.write()
                throw e
            }
        }
    }
"""),
    "uniffiTraitInterfaceCallAsync": ("""\
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
""", """\
        val callResult = try {
            makeCall()
        } catch(e: kotlin.Throwable) {
            handleError(
                UniffiRustCallStatus.create(
                    UNIFFI_CALL_UNEXPECTED_ERROR,
                    FfiConverterString.lower("CALLBACK_FAILURE"),
                )
            )
            if (e !is kotlin.Exception || e is kotlin.coroutines.cancellation.CancellationException) throw e
            return@coroutineBlock
        }
        handleSuccess(callResult)
"""),
    "uniffiTraitInterfaceCallAsyncWithError": ("""\
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
""", """\
        val callResult = try {
            makeCall()
        } catch(e: kotlin.Throwable) {
            val lowered = if (e is E) try { lowerError(e) } catch(unlowered: kotlin.Throwable) { null } else null
            if (lowered != null) {
                handleError(
                    UniffiRustCallStatus.create(
                        UNIFFI_CALL_ERROR,
                        lowered,
                    )
                )
            } else {
                handleError(
                    UniffiRustCallStatus.create(
                        UNIFFI_CALL_UNEXPECTED_ERROR,
                        FfiConverterString.lower("CALLBACK_FAILURE"),
                    )
                )
            }
            if (e !is kotlin.Exception || e is kotlin.coroutines.cancellation.CancellationException) throw e
            return@coroutineBlock
        }
        handleSuccess(callResult)
"""),
}
SWIFT_WRAPPERS = {
    "uniffiTraitInterfaceCall": ("""\
    do {
        try writeReturn(makeCall())
    } catch let error {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
""", """\
    do {
        try writeReturn(makeCall())
    } catch {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower("CALLBACK_FAILURE")
    }
"""),
    "uniffiTraitInterfaceCallWithError": ("""\
    do {
        try writeReturn(makeCall())
    } catch let error as E {
        callStatus.pointee.code = CALL_ERROR
        callStatus.pointee.errorBuf = lowerError(error)
    } catch {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
""", """\
    do {
        try writeReturn(makeCall())
    } catch let error as E {
        callStatus.pointee.code = CALL_ERROR
        callStatus.pointee.errorBuf = lowerError(error)
    } catch {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower("CALLBACK_FAILURE")
    }
"""),
    "uniffiTraitInterfaceCallAsync": ("""\
        do {
            callResult = try await makeCall()
        } catch {
            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower(String(describing: error)))
            return
        }
        handleSuccess(callResult)
""", """\
        do {
            callResult = try await makeCall()
        } catch {
            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower("CALLBACK_FAILURE"))
            return
        }
        handleSuccess(callResult)
"""),
    "uniffiTraitInterfaceCallAsyncWithError": ("""\
        do {
            callResult = try await makeCall()
        } catch let error as E {
            handleError(CALL_ERROR, lowerError(error))
            return
        } catch {
            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower(String(describing: error)))
            return
        }
        handleSuccess(callResult)
""", """\
        do {
            callResult = try await makeCall()
        } catch let error as E {
            handleError(CALL_ERROR, lowerError(error))
            return
        } catch {
            handleError(CALL_UNEXPECTED_ERROR, FfiConverterString.lower("CALLBACK_FAILURE"))
            return
        }
        handleSuccess(callResult)
"""),
}
# The rest of each wrapper, as generated and without its comment lines: what comes before
# its block, from its declaration on, and what comes after, to its closing brace. A wrapper
# is guarded only when the whole function is the generated one, so nothing that calls the
# host's method stands outside the guarded block.
KOTLIN_SHELLS = {
    "uniffiTraitInterfaceCall": ("""\
internal inline fun<T> uniffiTraitInterfaceCall(
    callStatus: UniffiRustCallStatus,
    makeCall: () -> T,
    writeReturn: (T) -> Unit,
) {
""", """\
}
"""),
    "uniffiTraitInterfaceCallWithError": ("""\
internal inline fun<T, reified E: Throwable> uniffiTraitInterfaceCallWithError(
    callStatus: UniffiRustCallStatus,
    makeCall: () -> T,
    writeReturn: (T) -> Unit,
    lowerError: (E) -> RustBuffer.ByValue
) {
""", """\
}
"""),
    "uniffiTraitInterfaceCallAsync": ("""\
internal inline fun<T> uniffiTraitInterfaceCallAsync(
    crossinline makeCall: suspend () -> T,
    crossinline handleSuccess: (T) -> Unit,
    crossinline handleError: (UniffiRustCallStatus.ByValue) -> Unit,
): UniffiForeignFuture {
    @OptIn(DelicateCoroutinesApi::class)
    val job = GlobalScope.launch coroutineBlock@ {
""", """\
    }
    val handle = uniffiForeignFutureHandleMap.insert(job)
    return UniffiForeignFuture(handle, uniffiForeignFutureFreeImpl)
}
"""),
    "uniffiTraitInterfaceCallAsyncWithError": ("""\
internal inline fun<T, reified E: Throwable> uniffiTraitInterfaceCallAsyncWithError(
    crossinline makeCall: suspend () -> T,
    crossinline handleSuccess: (T) -> Unit,
    crossinline handleError: (UniffiRustCallStatus.ByValue) -> Unit,
    crossinline lowerError: (E) -> RustBuffer.ByValue,
): UniffiForeignFuture {
    @OptIn(DelicateCoroutinesApi::class)
    val job = GlobalScope.launch coroutineBlock@ {
""", """\
    }
    val handle = uniffiForeignFutureHandleMap.insert(job)
    return UniffiForeignFuture(handle, uniffiForeignFutureFreeImpl)
}
"""),
}
SWIFT_SHELLS = {
    "uniffiTraitInterfaceCall": ("""\
private func uniffiTraitInterfaceCall<T>(
    callStatus: UnsafeMutablePointer<RustCallStatus>,
    makeCall: () throws -> T,
    writeReturn: (T) -> ()
) {
""", """\
}
"""),
    "uniffiTraitInterfaceCallWithError": ("""\
private func uniffiTraitInterfaceCallWithError<T, E>(
    callStatus: UnsafeMutablePointer<RustCallStatus>,
    makeCall: () throws -> T,
    writeReturn: (T) -> (),
    lowerError: (E) -> RustBuffer
) {
""", """\
}
"""),
    "uniffiTraitInterfaceCallAsync": ("""\
private func uniffiTraitInterfaceCallAsync<T>(
    makeCall: @escaping () async throws -> T,
    handleSuccess: @escaping (T) -> (),
    handleError: @escaping (Int8, RustBuffer) -> ()
) -> UniffiForeignFuture {
    let task = Task {
        var callResult: T
""", """\
    }
    let handle = UNIFFI_FOREIGN_FUTURE_HANDLE_MAP.insert(obj: task)
    return UniffiForeignFuture(handle: handle, free: uniffiForeignFutureFree)

}
"""),
    "uniffiTraitInterfaceCallAsyncWithError": ("""\
private func uniffiTraitInterfaceCallAsyncWithError<T, E>(
    makeCall: @escaping () async throws -> T,
    handleSuccess: @escaping (T) -> (),
    handleError: @escaping (Int8, RustBuffer) -> (),
    lowerError: @escaping (E) -> RustBuffer
) -> UniffiForeignFuture {
    let task = Task {
        var callResult: T
""", """\
    }
    let handle = UNIFFI_FOREIGN_FUTURE_HANDLE_MAP.insert(obj: task)
    return UniffiForeignFuture(handle: handle, free: uniffiForeignFutureFree)
}
"""),
}


def without_comments(text):
    """`text` without the lines that hold only a comment."""
    return "".join(line for line in text.splitlines(keepends=True)
                   if not line.lstrip().startswith("//"))


def guard_wrappers(source, language, declaration, entry, wrappers, shells):
    """Replace, in every wrapper `source` declares, the generated block with the guarded
    one. Refuse a wrapper that isn't, comments aside, the generated function, and a host
    callback that isn't called through a guarded wrapper for a method that declares a
    failure."""
    declared = set()
    for name, (generated, guarded) in wrappers.items():
        found = re.search(declaration.format(name=name), source, re.MULTILINE)
        if not found:
            continue
        declared.add(name)
        end = source.index("\n}\n", found.end()) + len("\n}\n")
        function = source[found.start():end]
        head, tail = shells[name]
        if without_comments(function) != head + generated + tail or function.count(generated) != 1:
            raise ValueError(f"{language}: {name} isn't the callback wrapper expected")
        guarded = guarded.replace("CALLBACK_FAILURE", CALLBACK_FAILURE)
        source = source[:found.start()] + function.replace(generated, guarded) + source[end:]
    calls = re.findall(r"^\s+(?:let \w+ = )?(uniffiTraitInterfaceCall\w*)\(", source, re.MULTILINE)
    if not set(calls) <= declared:
        raise ValueError(f"{language}: a callback wrapper isn't guarded: {sorted(set(calls) - declared)}")
    untyped = [name for name in calls if not name.endswith("WithError")]
    if untyped:
        raise ValueError(f"{language}: a host callback method declares no failure")
    if len(re.findall(entry, source, re.MULTILINE)) != len(calls):
        raise ValueError(f"{language}: a host callback isn't called through a guarded wrapper")
    return source


def guard_callbacks(kotlin, swift):
    """Report what a host callback's method throws to Rust as a failure, with no host text.

    UniFFI's Kotlin catches `Exception` only. Any other `Throwable`, such as an
    `AssertionError` or an `OutOfMemoryError`, would leave a synchronous call's status as
    Rust set it: success, so a callback that returns nothing would be read as having
    returned. In an asynchronous callback it would end the coroutine with neither
    completion called, and Rust would wait for ever, as it would for a typed failure the
    Kotlin can't lower, such as one whose text isn't valid Unicode. Both generators also
    hand Rust a description of what was thrown, which may quote whatever the host put in
    it. Swift's `catch` already catches everything thrown, and its lowering can't fail.
    `KOTLIN_WRAPPERS` and `SWIFT_WRAPPERS` hold what each wrapper becomes.

    This guards the wrappers' handlers, not the generated code around them: the README
    says what stays outside. A generator that shapes a wrapper differently is refused,
    not left unguarded. So is a callback method that declares no failure: UniFFI has
    nowhere to report one for it.
    """
    kotlin = guard_wrappers(
        kotlin, "Kotlin", r"^internal inline fun<[^>]*> {name}\(",
        r"^\s+internal object `[^`]+`: UniffiCallbackInterface\w+Method\d+ \{$",
        KOTLIN_WRAPPERS, KOTLIN_SHELLS,
    )
    if re.search(r"catch\s*\(\s*\w+\s*:\s*(?:kotlin\.)?Exception\s*\)\s*\{", kotlin):
        raise ValueError("Kotlin: a generated handler catches Exception only")
    if "lower(e.toString())" in kotlin:
        raise ValueError("Kotlin: a generated handler describes what was thrown")
    swift = guard_wrappers(
        swift, "Swift", r"^private func {name}<[^>]*>\(",
        r"^\s+uniffiHandle: UInt64,$",
        SWIFT_WRAPPERS, SWIFT_SHELLS,
    )
    if "lower(String(describing: error))" in swift:
        raise ValueError("Swift: a generated handler describes what was thrown")
    return kotlin, swift


def check_objects(kotlin):
    """Refuse an exported object that isn't listed as opaque, or isn't used as one.

    Lowered on its way to Rust, a handle skips the guard a method call gets against a
    handle the host closed. So every object a build exports is listed, and none listed is
    generated as a value described field by field, passed as an argument, or passed inside
    a list, an option, a record or an enum. Such a value may still come back from Rust,
    which makes a new handle each time: only lowering one is refused.
    """
    objects = set(re.findall(r"^open class (\w+)\s*:[^{\n]*\bDisposable\b", kotlin, re.MULTILINE))
    if objects - OPAQUE:
        raise ValueError(f"exported objects not listed as opaque: {sorted(objects - OPAQUE)}")
    handles = {f"FfiConverterType{name}" for name in OPAQUE}
    for name in sorted(OPAQUE):
        if re.search(rf"^(?:data|sealed) class {name}\b", kotlin, re.MULTILINE):
            raise ValueError(f"{name} is generated as a described value")
        if f"FfiConverterType{name}.lower(" in kotlin:
            raise ValueError(f"{name} is passed as an argument")
    # The converter of a value that holds a handle writes it through the handle's own
    # converter, and so does the converter of a value that holds such a value.
    converters = dict(re.findall(r"^public object (FfiConverter\w+)\b[^{\n]*\{\n(.*?)^\}",
                                 kotlin, re.MULTILINE | re.DOTALL))
    holding = set(handles)
    grown = True
    while grown:
        grown = False
        for converter, body in converters.items():
            if converter not in holding and any(f"{held}.write(" in body for held in holding):
                holding.add(converter)
                grown = True
    for converter in sorted(holding - handles):
        if f"{converter}.lower(" in kotlin:
            raise ValueError(f"an opaque object is passed inside a value: {converter}")


def redact(kotlin_path, swift_source_path, swift_path):
    kotlin = kotlin_path.read_text()
    swift_source = swift_source_path.read_text()
    # UniFFI's buffer length already matches the JNA signature. Kotlin 2.3 diagnoses the
    # redundant conversion when the host build treats warnings as errors.
    length = "getByteBuffer(0, this.len.toLong())"
    if kotlin.count(length) != 1:
        raise ValueError("expected one generated JNA buffer method")
    kotlin = kotlin.replace(length, "getByteBuffer(0, this.len)")
    kotlin, swift_source = guard_callbacks(kotlin, swift_source)
    check_objects(kotlin)
    # A flat error carries its Display text as a message the script can't redact: errors
    # declare fields instead.
    flat = re.findall(r"^sealed class (\w+)\(message: String\)", kotlin, re.MULTILINE)
    if flat:
        raise ValueError(f"flat errors aren't redacted: {flat}")
    types = re.findall(r"^(?:data|sealed) class (\w+)\b", kotlin, re.MULTILINE)
    if not PUBLIC.issubset(types):
        raise ValueError("unexpected generated Kotlin value declarations")
    converters = {
        target: wire for wire, target in re.findall(
            r"^public object FfiConverterType(\w+)\s*:\s*FfiConverterRustBuffer<(\w+)>",
            kotlin, re.MULTILINE,
        )
    }
    swift = []
    for kotlin_name in types:
        if kotlin_name in PUBLIC:
            continue
        name = converters[kotlin_name]
        sealed = rf"^sealed class {kotlin_name}\b[^{{\n]*\{{\n"
        record = rf"^data class {kotlin_name} \(\n.*?^\)[^{{\n]*\{{\n"
        pattern = sealed if re.search(sealed, kotlin, re.MULTILINE) else record
        override = "final override" if pattern == sealed else "override"
        kotlin, count = re.subn(
            pattern,
            lambda m: m[0] + f'    {override} fun toString(): String = "{kotlin_name}(<redacted>)"\n',
            kotlin,
            flags=re.MULTILINE | re.DOTALL,
        )
        if count != 1:
            raise ValueError(f"expected one generated Kotlin declaration for {name}")
        thrown = re.search(rf"^sealed class {kotlin_name}\s*:\s*kotlin\.Exception\(\)",
                           kotlin, re.MULTILINE)
        if thrown:
            # An error, whatever its name: UniFFI also puts variant fields into its
            # Throwable.message.
            start = thrown.start()
            end = kotlin.index("\n}", start)
            body, count = re.subn(r'(override val message\n\s+get\(\) = )"[^\n]*"',
                                  r"\g<1>toString()", kotlin[start:end])
            variants = len(re.findall(r"^    (?:class|object) \w+", kotlin[start:end], re.MULTILINE))
            left = re.search(r'override val message\n\s+get\(\) = "', body)
            if not count or count != variants or left:
                raise ValueError(f"not every message of {kotlin_name} is redacted")
            kotlin = kotlin[:start] + body + kotlin[end:]
        if not re.search(rf"^public (?:struct|enum) {name}\b", swift_source, re.MULTILINE):
            raise ValueError(f"{name} isn't in the generated Swift")
        if re.search(rf"^extension {name}\s*:\s*[^{{]*CustomStringConvertible", swift_source,
                     re.MULTILINE):
            raise ValueError(f"the generated Swift already describes {name}")
        swift.append(f"""extension {name}: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {{
    public var description: String {{ "{name}(<redacted>)" }}
    public var debugDescription: String {{ description }}
    public var customMirror: Mirror {{ Mirror(self, children: [:]) }}
}}
""")
    kotlin_path.write_text(kotlin)
    swift_source_path.write_text(swift_source)
    swift_path.write_text("// Generated by prepare-bindings.py.\n" + "\n".join(swift))


if __name__ == "__main__":
    redact(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
