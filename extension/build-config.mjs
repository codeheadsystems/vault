// The esbuild configuration that build.mjs uses, shared with the bundle checks in
// test/manifest.test.ts so that they scan exactly what the build ships.

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const root = dirname(fileURLToPath(import.meta.url));
export const glueOut = join(root, "build", "wasm", "vault_wasm.js");
export const stubPath = join(root, "src", "shared", "wasm-stub.ts");

/** One bundle per context; the keys are the output names in dist/. */
export const entryPoints = {
  background: "src/background/main.ts",
  popup: "src/popup/popup.ts",
  page: "src/page/page.ts",
  watcher: "src/save/watcher.ts",
};

/** The glue the bundles import as "vault-wasm": the wasm-bindgen output once generated, else the
 * stub. */
export function currentGlue() {
  return existsSync(glueOut) ? glueOut : stubPath;
}

/**
 * esbuild options: unminified IIFE bundles for Firefox 153. `e2eTiming` shortens the idle check
 * and the clipboard clear for the end-to-end suite (src/shared/timing.ts).
 * @param {string} glue
 * @param {boolean} [e2eTiming]
 * @returns {import("esbuild").BuildOptions}
 */
export function esbuildOptions(glue, e2eTiming = false) {
  return {
    entryPoints,
    absWorkingDir: root,
    bundle: true,
    format: "iife",
    target: "firefox153",
    minify: false,
    charset: "utf8",
    legalComments: "inline",
    alias: { "vault-wasm": glue },
    // The glue falls back to import.meta.url only when no module path is given; the extension
    // always gives one (src/shared/wasm.ts).
    define: { "import.meta.url": "self.location.href", __VAULT_E2E_TIMING__: String(e2eTiming) },
    logLevel: "warning",
  };
}
