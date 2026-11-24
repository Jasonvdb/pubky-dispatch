"""Protect the generated descriptions of binding values, and a host callback's failure.

UniFFI describes a record or an enum with fields field by field, in Kotlin's toString,
an exception's message and Swift's description and reflection. Every such value the
bindings generate is redacted unless it is on PUBLIC below, whose fields carry nothing a
host must keep private. A secret never crosses in such a value at all: it crosses into an
opaque handle (OPAQUE), which this script checks the generator kept opaque.

A host callback that fails, whatever it throws, reaches Rust as a failure, and what it
threw hands no text of the host's to Rust (`guard_callbacks`).
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


def guard_wrappers(source, language, declaration, entry, rewrites, typed_rewrites):
    """Apply `rewrites` once each in every wrapper `source` declares, and `typed_rewrites`
    too in those serving a method that declares a failure. Refuse a wrapper shaped
    differently, and a host callback that isn't called through a guarded wrapper for a
    method that declares a failure."""
    declared = set()
    for name in WRAPPERS:
        found = re.search(declaration.format(name=name), source, re.MULTILINE)
        if not found:
            continue
        declared.add(name)
        end = source.index("\n}\n", found.end())
        body = source[found.end():end]
        typed = typed_rewrites if name.endswith("WithError") else []
        for old, new in rewrites + typed:
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


def guard_callbacks(kotlin, swift):
    """Make what a host callback throws reach Rust as a failure, with no host text.

    UniFFI's Kotlin catches `Exception` only. Any other `Throwable`, such as an
    `AssertionError` or an `OutOfMemoryError`, would leave a synchronous call's status as
    Rust set it: success, so a callback that returns nothing would be read as having
    returned. In an asynchronous callback it would end the coroutine with neither
    completion called, and Rust would wait for ever. So would a typed failure the Kotlin
    can't lower, such as one whose text isn't valid Unicode: it is reported as an
    unexpected failure instead. Both generators also hand Rust a description of what was
    thrown, which may quote whatever the host put in it. Swift's `catch` already catches
    everything thrown, and its lowering can't fail.

    A generator that shapes any of this differently is refused, not left unguarded. So is
    a callback method that declares no failure: UniFFI has nowhere to report one for it.
    """
    failure = f'FfiConverterString.lower("{CALLBACK_FAILURE}")'
    kotlin = guard_wrappers(
        kotlin, "Kotlin", r"^internal inline fun<[^>]*> {name}\(",
        r"^\s+internal object `[^`]+`: UniffiCallbackInterface\w+Method\d+ \{$",
        [(r"\} catch\(e: kotlin\.Exception\) \{", "} catch(e: kotlin.Throwable) {"),
         (r"FfiConverterString\.lower\(e\.toString\(\)\)", failure)],
        [(r"^( +)if \(e is E\) \{$",
          r"\1val lowered = if (e is E) try { lowerError(e) } "
          r"catch(unlowered: kotlin.Throwable) { null } else null\n\1if (lowered != null) {"),
         (r"(?<=[ =])lowerError\(e\)(?=,?$)", "lowered")],
    )
    if re.search(r"catch\s*\(\s*\w+\s*:\s*(?:kotlin\.)?Exception\s*\)\s*\{", kotlin):
        raise ValueError("Kotlin: a generated handler catches Exception only")
    if "lower(e.toString())" in kotlin:
        raise ValueError("Kotlin: a generated handler describes what was thrown")
    swift = guard_wrappers(
        swift, "Swift", r"^private func {name}<[^>]*>\(",
        r"^\s+uniffiHandle: UInt64,$",
        [(r"FfiConverterString\.lower\(String\(describing: error\)\)", failure)], [],
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
