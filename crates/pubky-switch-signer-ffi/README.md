# pubky-switch-signer-ffi

Kotlin and Swift bindings of the Pubky Switch signer (`pubky-switch-signer`), generated with
UniFFI from the compiled library. Signing, verification, recovery decisions and retry ordering
stay in Rust.

## Secrets

A secret, such as the identity's seed, only ever travels from the host into Rust. It crosses
once, into an opaque handle (`HostSecret`). Rust zeroizes it as soon as it is used, and nothing
the bindings return, throw or describe contains it. Every value the generator would describe
field by field is redacted by `prepare-bindings.py`, unless that script lists it as public.

## Generating the bindings

```sh
cargo build --release -p pubky-switch-signer-ffi --features bindgen --lib --bin pubky-switch-signer-bindgen
crates/pubky-switch-signer-ffi/generate-bindings.sh \
  target/release/pubky-switch-signer-bindgen target/release/libpubky_switch_signer_ffi.dylib OUT
```

`OUT/kotlin` holds the Kotlin package `pubky.switch.signer` and `OUT/swift` the Swift module
`PubkySwitchSigner` with its C module map. `tests/hosts` holds a Kotlin and a Swift host program
that CI builds against them and runs.
