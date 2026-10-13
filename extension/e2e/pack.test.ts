// End-to-end: the packed .xpi, as `npm run pack` writes it, installs in Firefox and runs.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { pack } from "../pack.mjs";
import { BASE, EXTENSION_ID, Firefox, waitFor } from "./lib/firefox.ts";

test("the packed .xpi installs and its background script answers", async () => {
  const xpi = pack();
  const ff = await Firefox.start();
  try {
    await ff.cmd("POST", "/moz/addon/install", { addon: readFileSync(xpi).toString("base64"), temporary: true });
    await waitFor("the background script", () => ff.chrome<boolean>(
      `const done = arguments[arguments.length - 1];
       done(WebExtensionPolicy.getByID(arguments[0])?.extension?.backgroundState === "running");`, EXTENSION_ID));
    await ff.nav(`${BASE}page.html`);
    const r = await ff.jsAsync<{ ok: boolean; value: { configured: boolean } }>(
      "const done = arguments[0]; browser.runtime.sendMessage({ type: 'status' }).then(done);");
    assert.deepEqual(r, { ok: true, value: { configured: false, unlocked: false, settings: { idleMinutes: 15 } } });
  } finally {
    await ff.quit();
  }
});
