#!/bin/sh
# Generate the Kotlin and Swift sources from a built signer library, then protect the
# descriptions of every generated value that isn't on the redaction script's public list.
set -eu
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 BINDGEN NATIVE_LIBRARY OUTPUT_DIRECTORY" >&2
    exit 2
fi
bindgen=$1
library=$2
out=$3
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$out/kotlin" "$out/swift"
for language in kotlin swift; do
    "$bindgen" generate --no-format --metadata-no-deps --library "$library" \
        --config "$dir/uniffi.toml" --language "$language" --out-dir "$out/$language"
done
kotlin=$out/kotlin/pubky/switch/signer/pubky_switch_signer_ffi.kt
for generated in "$kotlin" "$out/swift/PubkySwitchSigner.swift" "$out/swift/PubkySwitchSignerFFI.h" \
    "$out/swift/PubkySwitchSignerFFI.modulemap"; do
    if [ ! -s "$generated" ]; then
        echo "$0: the generator wrote no $generated" >&2
        exit 1
    fi
done
python3 "$dir/prepare-bindings.py" "$kotlin" "$out/swift/PubkySwitchSigner.swift" \
    "$out/swift/Redaction.swift"
