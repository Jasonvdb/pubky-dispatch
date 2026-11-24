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

Whatever a host callback's method throws is a failure of the call it served. The generated
Kotlin catches `Exception` only. Any other `Throwable` would leave a synchronous callback that
returns nothing read as having returned, and an asynchronous one never completed; so would a
typed failure the Kotlin can't lower. `prepare-bindings.py` makes the generated code catch every
`Throwable` and report a failure it can't lower as an unexpected one. It also replaces the
description of what was thrown, which both generators hand to Rust, with a fixed text. It
refuses generated code whose callback handling it doesn't recognise, and a callback method that
declares no failure, which would have nowhere to report one.

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
