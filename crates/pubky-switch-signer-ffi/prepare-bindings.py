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

# Values whose fields are public: an identity's public half, and the typed error, which
# names a failure's class and rule only.
PUBLIC = {"PublicIdentity", "SignerFfiException"}
# Handles a secret crosses into: generated as objects, never described field by field.
OPAQUE = {"HostSecret"}
# What Rust is handed in place of the text of what a host callback threw.
CALLBACK_FAILURE = "a host callback failed"


# UniFFI's wrappers around a host callback: the two synchronous forms, and the two an
# asynchronous callback is launched through. The forms named `WithError` serve a method
# that declares a failure; the others have nowhere to report one.
WRAPPERS = (
    "uniffiTraitInterfaceCall",
    "uniffiTraitInterfaceCallWithError",
    "uniffiTraitInterfaceCallAsync",
    "uniffiTraitInterfaceCallAsyncWithError",
)


def guard_wrappers(source, language, declaration, entry, rewrites):
    """Apply to every wrapper `source` declares the rewrites `rewrites` gives for its name,
    once each. Refuse a wrapper shaped differently, and a host callback that isn't called
    through a guarded wrapper for a method that declares a failure."""
    declared = set()
    for name in WRAPPERS:
        found = re.search(declaration.format(name=name), source, re.MULTILINE)
        if not found:
            continue
        declared.add(name)
        end = source.index("\n}\n", found.end())
        body = source[found.end():end]
        for old, new in rewrites(name):
            body, count = re.subn(old, new, body, flags=re.MULTILINE)
            if count != 1:
                raise ValueError(f"{language}: {name} isn't the callback wrapper expected")
        source = source[:found.end()] + body + source[end:]
    calls = re.findall(r"^\s+(?:let \w+ = )?(uniffiTraitInterfaceCall\w*)\(", source, re.MULTILINE)
    if not set(calls) <= declared:
        raise ValueError(f"{language}: a callback wrapper isn't guarded: {sorted(set(calls) - declared)}")
    untyped = [name for name in calls if not name.endswith("WithError")]
    if untyped:
        raise ValueError(f"{language}: a host callback method declares no failure")
    if len(re.findall(entry, source, re.MULTILINE)) != len(calls):
        raise ValueError(f"{language}: a host callback isn't called through a guarded wrapper")
    return source


def kotlin_rewrites(name):
    """The rewrites of one Kotlin wrapper. Each matches the status the wrapper reports
    together with what it hands over, so a wrapper that reports none is refused."""
    failure = f'FfiConverterString.lower("{CALLBACK_FAILURE}")'
    # Reported first, then thrown on: an `Error` reaches the handler the platform reports
    # it through, and a cancellation still cancels its coroutine.
    rethrow = "if (e !is kotlin.Exception) throw e"
    rethrow_async = ("if (e !is kotlin.Exception || "
                     "e is kotlin.coroutines.cancellation.CancellationException) throw e")
    lowered = (r"\1val lowered = if (e is E) try { lowerError(e) } "
               r"catch(unlowered: kotlin.Throwable) { null } else null\n\1if (lowered != null) {")
    rewrites = [(r"\} catch\(e: kotlin\.Exception\) \{", "} catch(e: kotlin.Throwable) {")]
    if "Async" in name:
        rewrites += [
            (r"(UNIFFI_CALL_UNEXPECTED_ERROR,\n\s+)FfiConverterString\.lower\(e\.toString\(\)\),",
             rf"\1{failure},"),
            (r"^( +)return@coroutineBlock$", rf"\1{rethrow_async}\n\1return@coroutineBlock"),
        ]
        typed = [(r"(UNIFFI_CALL_ERROR,\n\s+)lowerError\(e\),", r"\1lowered,")]
    else:
        rewrites += [
            (r"^( +)(callStatus\.code = UNIFFI_CALL_UNEXPECTED_ERROR\n\1callStatus\.error_buf = )"
             r"FfiConverterString\.lower\(e\.toString\(\)\)$",
             rf"\1\2{failure}\n\1{rethrow}"),
        ]
        typed = [(r"(callStatus\.code = UNIFFI_CALL_ERROR\n\s+callStatus\.error_buf = )lowerError\(e\)$",
                  r"\1lowered")]
    if name.endswith("WithError"):
        rewrites += [(r"^( +)if \(e is E\) \{$", lowered)] + typed
    return rewrites


def swift_rewrites(name):
    """The rewrite of one Swift wrapper, matched with the status it reports."""
    failure = f'FfiConverterString.lower("{CALLBACK_FAILURE}")'
    described = r"FfiConverterString\.lower\(String\(describing: error\)\)"
    if "Async" in name:
        return [(rf"(handleError\(CALL_UNEXPECTED_ERROR, ){described}\)", rf"\1{failure})")]
    return [(rf"(callStatus\.pointee\.code = CALL_UNEXPECTED_ERROR\n\s+callStatus\.pointee\.errorBuf = )"
             rf"{described}$", rf"\1{failure}")]


def guard_callbacks(kotlin, swift):
    """Report what a host callback's method throws to Rust as a failure, with no host text.

    UniFFI's Kotlin catches `Exception` only. Any other `Throwable`, such as an
    `AssertionError` or an `OutOfMemoryError`, would leave a synchronous call's status as
    Rust set it: success, so a callback that returns nothing would be read as having
    returned. In an asynchronous callback it would end the coroutine with neither
    completion called, and Rust would wait for ever, as it would for a typed failure the
    Kotlin can't lower, such as one whose text isn't valid Unicode. Each is reported as an
    unexpected failure instead. What isn't an `Exception` is then thrown on, so the host
    still sees its own failure where the platform reports it. Both generators also hand
    Rust a description of what was thrown, which may quote whatever the host put in it:
    a fixed text replaces it. Swift's `catch` already catches everything thrown, and its
    lowering can't fail.

    This guards the wrappers' handlers, not the generated code around them: the README
    says what stays outside. A generator that shapes a wrapper differently is refused,
    not left unguarded. So is a callback method that declares no failure: UniFFI has
    nowhere to report one for it.
    """
    kotlin = guard_wrappers(
        kotlin, "Kotlin", r"^internal inline fun<[^>]*> {name}\(",
        r"^\s+internal object `[^`]+`: UniffiCallbackInterface\w+Method\d+ \{$",
        kotlin_rewrites,
    )
    if re.search(r"catch\s*\(\s*\w+\s*:\s*(?:kotlin\.)?Exception\s*\)\s*\{", kotlin):
        raise ValueError("Kotlin: a generated handler catches Exception only")
    if "lower(e.toString())" in kotlin:
        raise ValueError("Kotlin: a generated handler describes what was thrown")
    swift = guard_wrappers(
        swift, "Swift", r"^private func {name}<[^>]*>\(",
        r"^\s+uniffiHandle: UInt64,$",
        swift_rewrites,
    )
    # The first synchronous wrapper named the error only to describe it.
    swift = swift.replace("} catch let error {\n        callStatus.pointee.code = CALL_UNEXPECTED_ERROR",
                          "} catch {\n        callStatus.pointee.code = CALL_UNEXPECTED_ERROR")
    if "lower(String(describing: error))" in swift:
        raise ValueError("Swift: a generated handler describes what was thrown")
    return kotlin, swift


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
    for name in OPAQUE:
        if not re.search(rf"^open class {name}\b", kotlin, re.MULTILINE):
            raise ValueError(f"{name} isn't generated as an opaque object")
        if re.search(rf"^(?:data|sealed) class {name}\b", kotlin, re.MULTILINE):
            raise ValueError(f"{name} is generated as a described value")
        # Lowered as an argument, a handle skips the guard a method call gets against a
        # handle the host closed: it is used only through its own methods.
        if f"FfiConverterType{name}.lower(" in kotlin:
            raise ValueError(f"{name} is passed as an argument")
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
