// Builds the extension into dist/ (docs/firefox.md, Build and tests).
//
// 1. The WASM module: `cargo build -p vault-wasm --target wasm32-unknown-unknown --profile wasm`
//    from the workspace, so the module always matches the checked-out source; then wasm-bindgen's
//    `web` output and wasm-opt -O3. With VAULT_WASM_STUB=1 the build uses src/shared/wasm-stub.ts
//    instead and marks dist/ as a stub build, which `npm run sign` refuses. VAULT_E2E_TIMING=1
//    shortens the idle check and the clipboard clear for the end-to-end suite and marks dist/,
//    which `npm run sign` also refuses.
// 2. esbuild bundles each context's script, unminified, for Firefox 153.
// 3. The static files, and the manifest with the package version.
//
// WASM_BINDGEN names wasm-bindgen when it is not on PATH; it must match the wasm-bindgen crate
// version in Cargo.lock. WASM_OPT overrides the wasm-opt of the binaryen dev dependency.

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import * as esbuild from "esbuild";
import { esbuildOptions, glueOut, root, stubPath } from "./build-config.mjs";

const dist = join(root, "dist");
const target = process.env.CARGO_TARGET_DIR ?? join(root, "..", "target");
const wasmIn = join(target, "wasm32-unknown-unknown", "wasm", "vault_wasm.wasm");
const glueDir = dirname(glueOut);

function lockedBindgenVersion() {
  const lock = readFileSync(join(root, "..", "Cargo.lock"), "utf8");
  const m = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/);
  return m ? m[1] : null;
}

function buildWasm() {
  execFileSync("cargo", ["build", "-p", "vault-wasm", "--target", "wasm32-unknown-unknown", "--profile", "wasm"], {
    cwd: join(root, ".."), stdio: "inherit",
  });
  const bindgen = process.env.WASM_BINDGEN ?? "wasm-bindgen";
  const want = lockedBindgenVersion();
  const have = execFileSync(bindgen, ["--version"], { encoding: "utf8" }).trim().split(/\s+/)[1];
  if (want !== null && have !== want) {
    throw new Error(`wasm-bindgen CLI ${have} does not match the crate version ${want} in Cargo.lock`);
  }
  rmSync(glueDir, { recursive: true, force: true });
  execFileSync(bindgen, ["--target", "web", "--no-typescript", "--out-dir", glueDir, wasmIn], { stdio: "inherit" });
  // binaryen 132 or later: older wasm-opt cannot parse Rust 1.96's output. The npm package is a
  // pinned dev dependency, so no system install is needed.
  const opt = process.env.WASM_OPT ?? join(root, "node_modules", ".bin", "wasm-opt");
  execFileSync(opt, [
    "-O3", "--enable-simd", "--enable-bulk-memory", "--enable-multivalue", "--enable-mutable-globals",
    "--enable-nontrapping-float-to-int", "--enable-reference-types", "--enable-sign-ext",
    join(glueDir, "vault_wasm_bg.wasm"), "-o", join(dist, "vault_wasm_bg.wasm"),
  ], { stdio: "inherit" });
  return glueOut;
}

const stub = process.env.VAULT_WASM_STUB === "1";
const e2eTiming = process.env.VAULT_E2E_TIMING === "1";
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

let glue;
if (stub) {
  console.warn("build: VAULT_WASM_STUB=1; using the stub (src/shared/wasm-stub.ts)");
  glue = stubPath;
  writeFileSync(join(dist, "STUB"), "This build uses the vault-wasm stub and must not be shipped.\n");
} else {
  glue = buildWasm();
}

if (e2eTiming) writeFileSync(join(dist, "E2E_TIMING"), "This build has the end-to-end test timings and must not be shipped.\n");
await esbuild.build({ ...esbuildOptions(glue, e2eTiming), outdir: dist });

for (const f of ["popup.html", "page.html", "style.css", "icon.svg"]) {
  cpSync(join(root, "static", f), join(dist, f));
}
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(root, "static", "manifest.json"), "utf8"));
manifest.version = pkg.version;
if (stub) manifest.name += " (stub build)";
writeFileSync(join(dist, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`build: dist/ ${stub ? "(stub)" : "(vault-wasm)"}${e2eTiming ? " (e2e timing)" : ""} version ${pkg.version}`);
