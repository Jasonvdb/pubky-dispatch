#!/usr/bin/env node
// Runs one wasm-bindgen test binary of the signer in a headless browser driven by Playwright.
// Test code only.
//
// Cargo uses it as the wasm32 runner and passes the test .wasm file and the test arguments
// (test.sh sets this up):
//
//   CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="node /abs/path/browser/runner.mjs" \
//   SIGNER_BROWSER_ENGINE=chrome SIGNER_BROWSER_CONTEXT=worker \
//   cargo test -p pubky-dispatch-signer --target wasm32-unknown-unknown --test browser_flows
//
// Environment:
//   SIGNER_BROWSER_ENGINE        chromium (Playwright's headless Chromium) | chrome (the
//                                installed Google Chrome, headless). Default chromium.
//   SIGNER_BROWSER_CONTEXT       page | worker (a dedicated worker). Default page.
//   SIGNER_BROWSER_TIMEOUT_SECS  hard limit for the whole run. Default 300.
//   WASM_BINDGEN_TEST_RUNNER     the wasm-bindgen-test-runner binary. Default: from PATH.
//
// wasm-bindgen-test-runner runs with NO_HEADLESS=1, so it only generates the bindings and
// serves the test page on a free loopback port. This script opens that page in the engine,
// relays console output and errors, waits for the harness's "test result:" line, and exits 0
// only when at least one test ran and none failed. With a test name filter that matches no
// test, wasm-bindgen-test-runner says "no tests to run!" and exits without serving; this script
// then exits 0 too, and test.sh fails a run in which no PASS line was printed. The runner and
// the browser are stopped on every exit. Given `--list`, it only runs
// wasm-bindgen-test-runner, which prints the test names.

import { spawn } from "node:child_process";
import { chromium } from "playwright";

const ENGINES = {
  chromium: { type: chromium, options: {} },
  chrome: { type: chromium, options: { channel: "chrome" } },
};
// The wasm-bindgen-test-runner variable that selects each context.
const CONTEXTS = {
  page: "WASM_BINDGEN_USE_BROWSER",
  worker: "WASM_BINDGEN_USE_DEDICATED_WORKER",
};
// Every mode variable wasm-bindgen-test-runner 0.2.130 reads; it refuses more than one.
const MODE_VARIABLES = [
  "WASM_BINDGEN_USE_DENO",
  "WASM_BINDGEN_USE_BROWSER",
  "WASM_BINDGEN_USE_DEDICATED_WORKER",
  "WASM_BINDGEN_USE_SHARED_WORKER",
  "WASM_BINDGEN_USE_SERVICE_WORKER",
  "WASM_BINDGEN_USE_NODE_EXPERIMENTAL",
];
const RESULT_LINE = /test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;/g;
const NO_TESTS_LINE = /^no tests to run!\r?$/m;
// Matches only a complete line, so a URL split across output chunks is never taken early.
const SERVING_LINE = /available at (http:\/\/\S+)\r?\n/;

const engineName = process.env.SIGNER_BROWSER_ENGINE || "chromium";
const contextName = process.env.SIGNER_BROWSER_CONTEXT || "page";
const timeoutSecs = Number(process.env.SIGNER_BROWSER_TIMEOUT_SECS || 300);
const runnerBin = process.env.WASM_BINDGEN_TEST_RUNNER || "wasm-bindgen-test-runner";
const started = Date.now();

let child;
let browser;
let finished = false;

function log(line) {
  process.stdout.write(`${line}\n`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function errorText(error) {
  const message = error?.message ?? String(error);
  const stack = error?.stack ?? "";
  return stack.includes(message) ? stack : `${message}\n${stack}`.trimEnd();
}

// Stop the runner and the browser, then exit. Safe to call more than once.
async function finish(code, why) {
  if (finished) return;
  finished = true;
  if (why) log(`[runner] ${why}`);
  log(`[runner] elapsed ${((Date.now() - started) / 1000).toFixed(1)}s`);
  if (browser) await Promise.race([browser.close().catch(() => {}), sleep(5000)]);
  if (child && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    const exited = new Promise((resolve) => child.once("exit", resolve));
    if ((await Promise.race([exited.then(() => true), sleep(3000)])) !== true) {
      child.kill("SIGKILL");
    }
  }
  process.exit(code);
}

process.on("SIGINT", () => finish(130, "interrupted"));
process.on("SIGTERM", () => finish(143, "terminated"));
if (!(timeoutSecs > 0 && timeoutSecs <= 2147483)) {
  log("[runner] SIGNER_BROWSER_TIMEOUT_SECS must be a positive number, at most 2147483");
  process.exit(2);
}
setTimeout(
  () => finish(124, `timed out after ${timeoutSecs}s without a test result`),
  timeoutSecs * 1000,
);

// Whether the arguments after the module path narrow the tests to run.
function hasTestFilter(args) {
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--format") i += 1;
    else if (arg === "--skip" || arg.startsWith("--skip=") || !arg.startsWith("-")) return true;
  }
  return false;
}

// Start wasm-bindgen-test-runner in serve-only mode, and resolve with the page URL.
function serveTests(args) {
  const env = { ...process.env, NO_HEADLESS: "1", WASM_BINDGEN_TEST_ADDRESS: "127.0.0.1:0" };
  for (const name of MODE_VARIABLES) delete env[name];
  env[CONTEXTS[contextName]] = "1";
  const filtered = hasTestFilter(args.slice(1));

  return new Promise((resolve, reject) => {
    child = spawn(runnerBin, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let served = false;
    const relay = (stream, out) => {
      stream.setEncoding("utf8");
      stream.on("data", (chunk) => {
        out.write(chunk);
        if (served) return;
        output += chunk;
        const url = output.match(SERVING_LINE);
        if (url) {
          served = true;
          resolve(url[1]);
        }
      });
    };
    relay(child.stdout, process.stdout);
    relay(child.stderr, process.stderr);
    child.on("error", (error) => reject(new Error(`cannot start ${runnerBin}: ${error.message}`)));
    child.on("exit", (code, signal) => {
      if (served) finish(1, `${runnerBin} exited while serving (code ${code}, signal ${signal})`);
    });
    child.on("close", (code, signal) => {
      if (served) return;
      if (code === 0 && filtered && NO_TESTS_LINE.test(output)) {
        finish(0, "no test matched the filter");
        return;
      }
      reject(new Error(`${runnerBin} exited before serving (code ${code}, signal ${signal})`));
    });
  });
}

function checkResult(text) {
  const last = [...text.matchAll(RESULT_LINE)].at(-1);
  if (!last) return { error: "no parsable test result line" };
  const [, status, passed, failed] = last;
  const counts = `${passed} passed, ${failed} failed`;
  if (!(status === "ok" && Number(failed) === 0 && Number(passed) > 0)) {
    return { error: `the tests did not pass: ${counts}` };
  }
  return { counts };
}

async function main() {
  if (!Object.hasOwn(ENGINES, engineName)) {
    return finish(2, `unknown SIGNER_BROWSER_ENGINE "${engineName}"`);
  }
  if (!Object.hasOwn(CONTEXTS, contextName)) {
    return finish(2, `unknown SIGNER_BROWSER_CONTEXT "${contextName}"`);
  }
  const args = process.argv.slice(2);
  if (args.includes("--list")) {
    child = spawn(runnerBin, args, { stdio: "inherit" });
    child.on("error", (error) => finish(1, `cannot start ${runnerBin}: ${error.message}`));
    child.on("exit", (code) => {
      if (!finished) process.exit(code ?? 1);
    });
    return;
  }
  const engine = ENGINES[engineName];
  const url = await serveTests(args);
  browser = await engine.type.launch({ headless: true, ...engine.options });
  const page = await browser.newPage();
  const run = `${engineName} ${browser.version()} ${contextName}`;
  log(`[runner] engine ${run}, ${url}`);

  let workers = 0;
  let uncaught;
  page.on("console", (msg) => {
    if (!msg.worker?.()) log(`[page ${msg.type()}] ${msg.text()}`);
  });
  page.on("pageerror", (error) => {
    log(`[page error] ${errorText(error)}`);
    uncaught ??= `page error: ${error?.message ?? error}`;
  });
  page.on("crash", () => finish(1, "the page crashed"));
  page.on("worker", (worker) => {
    workers += 1;
    log(`[runner] dedicated worker started: ${worker.url()}`);
    worker.on("console", (msg) => {
      log(`[worker ${msg.type()}] ${msg.text()}`);
      if (msg.type() === "error") uncaught ??= `worker error: ${msg.text()}`;
    });
  });
  await page.goto(url);

  // The harness writes its report into #output and ends it with the "test result:" line.
  let printed = "";
  for (;;) {
    const text = await page.evaluate(() => document.getElementById("output")?.textContent ?? "");
    process.stdout.write(text.startsWith(printed) ? text.slice(printed.length) : `\n${text}`);
    printed = text;
    if (text.includes("test result: ")) break;
    if (text.includes("\nWorker error: ")) uncaught ??= "worker error, reported by the page";
    if (uncaught) return finish(1, `${uncaught} (before a test result)`);
    await sleep(100);
  }
  await sleep(200);
  if (contextName === "worker" && workers === 0) {
    return finish(1, "the tests reported, but no dedicated worker was seen");
  }
  const step = checkResult(printed);
  if (step.error) return finish(1, `FAIL ${run}: ${step.error}`);
  return finish(0, `PASS ${run}: ${step.counts}`);
}

main().catch((error) => finish(1, errorText(error)));
