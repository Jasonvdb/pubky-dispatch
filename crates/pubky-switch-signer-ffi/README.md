# pubky-switch-signer-ffi

Kotlin and Swift bindings of the Pubky Switch signer (`pubky-switch-signer`), generated with
UniFFI from the compiled library. Signing, verification, recovery decisions and retry ordering
stay in Rust.

## Secrets

A secret, such as the identity's seed, crosses the boundary only from the host into Rust, as the
bytes of a `HostSecret` handle or what a vault callback returns, and from Rust to the host as an
argument of the vault callbacks that add a secret or delete the expected one. No export returns
it, and no event, error or description carries it. Rust zeroizes its copy as soon as it is used.
The bindings' transfer copies are freed without a wipe, so a host keeps the secret in its vault
and hands it over only at the call. A handle is used only through its own methods, which the
bindings guard against a handle the host closed; it is never passed as an argument.
`prepare-bindings.py` enforces that, and redacts every value the generator would describe field
by field unless the script lists it as public.

## Host callbacks

What a host callback's method throws is reported to Rust as a failure of the call it served.

The Kotlin that UniFFI generates catches `Exception` only around a callback. Any other
`Throwable` thrown by a synchronous callback would leave the call's status as Rust set it,
success, so a callback that returns nothing would be read as having returned. Thrown by an
asynchronous callback it would leave the call never completed, and so would a typed failure the
Kotlin can't lower. `prepare-bindings.py` makes the generated code catch every `Throwable`, and
report a typed failure it can't lower as an unexpected one.

What the host sees:
- The call that needed the callback fails with its typed error.
- An `Exception` is consumed there, as it always was.
- Anything else, an `Error`, is thrown on once the failure is reported, so the platform reports
  it where it did before: JNA's callback exception handler (standard error unless the host set
  one) for a synchronous callback, and the thread's uncaught exception handler for an
  asynchronous one. The failure is with Rust before that, whatever the handler then does. A
  cancellation thrown by an asynchronous callback is thrown on too, so its coroutine ends
  cancelled.
- None of its text goes to Rust. Both generators hand Rust a description of what was thrown;
  the script replaces it with a fixed text.

The script refuses generated code whose callback handling it doesn't recognise, and a callback
method that declares no failure, which would have nowhere to report one.

This covers what the host's own method throws. A failure of the generated code around it, such
as a callback's handle that is no longer registered, or memory running out while the failure is
reported, isn't covered.

## Generating the bindings

```sh
cargo build --release -p pubky-switch-signer-ffi --features bindgen --lib --bin pubky-switch-signer-bindgen
crates/pubky-switch-signer-ffi/generate-bindings.sh \
  target/release/pubky-switch-signer-bindgen target/release/libpubky_switch_signer_ffi.dylib OUT
```

`OUT/kotlin` holds the Kotlin package `pubky.switch.signer` and `OUT/swift` the Swift module
`PubkySwitchSigner` with its C module map. `tests/hosts` holds a Kotlin and a Swift host program
that CI builds against them and runs.
