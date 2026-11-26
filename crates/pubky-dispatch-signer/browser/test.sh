#!/usr/bin/env bash
# Run the signer's browser tests (tests/browser_flows.rs) as wasm32-unknown-unknown in a headless
# browser, through Playwright (runner.mjs). Test code only.
#
#   crates/pubky-dispatch-signer/browser/test.sh [chromium|chrome|both] [page|worker|both] [cargo test args...]
#
# "chromium" is Playwright's headless Chromium, "chrome" the installed Google Chrome, headless.
# Both default to "both". Further arguments go to `cargo test`, such as a test name filter.
#
# Needs:
# - the wasm32-unknown-unknown Rust target;
# - wasm-bindgen-test-runner on PATH, or in WASM_BINDGEN_TEST_RUNNER, at the wasm-bindgen
#   version of Cargo.lock: `cargo install wasm-bindgen-cli --version <that version> --locked`;
# - `npm ci --ignore-scripts` run in this folder, and Playwright's Chromium
#   (`npx playwright install chromium`) for the chromium engine.
#
# The same tests run natively in `cargo test -p pubky-dispatch-signer`, and both builds check
# the same fixed vector (tests/browser_flows.rs).

set -euo pipefail

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 [chromium|chrome|both] [page|worker|both] [cargo test args...]" >&2
  exit 2
}

case "${1:-both}" in
  both) engines=(chromium chrome) ;;
  chromium | chrome) engines=("$1") ;;
  *) usage ;;
esac
case "${2:-both}" in
  both) contexts=(page worker) ;;
  page | worker) contexts=("$2") ;;
  *) usage ;;
esac
shift $(($# >= 2 ? 2 : $#))

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../../.." && pwd)
[[ "$here" =~ [[:space:]] ]] && die "the path $here contains whitespace, which a cargo runner setting cannot hold"
[[ -d "$here/node_modules/playwright" ]] ||
  die "Playwright is not installed; run: (cd $here && npm ci --ignore-scripts)"

# wasm-bindgen-cli generates the bindings the test binary links against, so it must be exactly
# the wasm-bindgen version of Cargo.lock.
locked=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print }' "$root/Cargo.lock")
[[ -n "$locked" && "$locked" != *$'\n'* ]] || die "Cargo.lock holds no single wasm-bindgen version"
runner_bin=${WASM_BINDGEN_TEST_RUNNER:-wasm-bindgen-test-runner}
command -v "$runner_bin" >/dev/null 2>&1 ||
  die "$runner_bin not found; install it with: cargo install wasm-bindgen-cli --version $locked --locked"
installed=$("$runner_bin" --version | awk '{ print $2 }')
[[ "$installed" == "$locked" ]] ||
  die "$runner_bin is $installed, but Cargo.lock has wasm-bindgen $locked"
export WASM_BINDGEN_TEST_RUNNER=$runner_bin
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="node $here/runner.mjs"

log=$(mktemp "${TMPDIR:-/tmp}/signer-browser.XXXXXX")
trap 'rm -f "$log"' EXIT

failed=()
for engine in "${engines[@]}"; do
  for context in "${contexts[@]}"; do
    echo "== $engine, $context"
    status=0
    SIGNER_BROWSER_ENGINE=$engine SIGNER_BROWSER_CONTEXT=$context \
      cargo test --locked --manifest-path "$root/Cargo.toml" -p pubky-dispatch-signer \
      --target wasm32-unknown-unknown --test browser_flows "$@" 2>&1 | tee "$log" || status=$?
    if [[ $status -ne 0 ]]; then
      failed+=("$engine/$context")
    elif ! grep -q '^\[runner\] PASS ' "$log"; then
      echo "error: no test ran in $engine/$context; check the test name filter" >&2
      failed+=("$engine/$context")
    fi
  done
done

if [[ ${#failed[@]} -gt 0 ]]; then
  echo "failed: ${failed[*]}" >&2
  exit 1
fi
echo "all passed: ${engines[*]} x ${contexts[*]}"
