# pubky-dispatch-signer-ffi

Kotlin and Swift bindings of the Pubky Dispatch signer (`pubky-dispatch-signer`), generated with
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

## Generating the bindings

```sh
cargo build --release -p pubky-dispatch-signer-ffi --features bindgen --lib --bin pubky-dispatch-signer-bindgen
crates/pubky-dispatch-signer-ffi/generate-bindings.sh \
  target/release/pubky-dispatch-signer-bindgen target/release/libpubky_dispatch_signer_ffi.dylib OUT
```

`OUT/kotlin` holds the Kotlin package `pubky.dispatch.signer` and `OUT/swift` the Swift module
`PubkyDispatchSigner` with its C module map. `tests/hosts` holds a Kotlin and a Swift host program
that CI builds against them and runs.
