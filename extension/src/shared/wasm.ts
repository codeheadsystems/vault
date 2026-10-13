// Loading vault-wasm once per context. The build bundles wasm-bindgen's `web` glue (or the stub)
// into each context's script and ships the module as vault_wasm_bg.wasm.

import init from "vault-wasm";

let ready: Promise<void> | null = null;

export function loadWasm(): Promise<void> {
  ready ??= init({ module_or_path: browser.runtime.getURL("vault_wasm_bg.wasm") }).then(() => undefined);
  return ready;
}

/** Known public suffixes from Firefox's own list (spec, Registrable domain). The function is
 * synchronous and throws on a host it cannot parse, which vault-wasm counts as a failed answer. */
export function knownSuffix(host: string): string | null {
  return browser.publicSuffix.getKnownSuffix(host);
}
