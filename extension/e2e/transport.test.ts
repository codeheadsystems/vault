// End-to-end: the Firefox transport rows of docs/requirements.md (Transport), through the
// extension's own setup flow and requests, against a real vault serve with its generated
// self-signed certificate. Each case runs in a fresh profile, because certificate exceptions
// persist in it.

import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { Ext } from "./lib/ext.ts";
import { BASE, waitFor } from "./lib/firefox.ts";
import { VaultServe } from "./lib/serve.ts";

let a: VaultServe; // certificate A
let b: VaultServe; // certificate B

before(async () => {
  a = await VaultServe.start({ https: true });
  b = await VaultServe.start({ https: true });
});

after(async () => {
  await a?.stop();
  await b?.stop();
});

const fingerprint = (s: VaultServe) => new X509Certificate(readFileSync(s.certPem())).fingerprint256;

/** Starts setup in a fresh profile and returns the session at step 2. */
async function startSetup(setupText: string, prefs: Record<string, unknown> = {}, before?: (ext: Ext) => Promise<void>): Promise<Ext> {
  const ext = await Ext.start(prefs);
  if (before) await before(ext);
  await ext.vaultPage("setup");
  await waitFor("setup form", () => ext.ff.exists("#setup-text"));
  await ext.ff.type("#setup-text", setupText);
  await ext.ff.click("#setup-continue");
  await waitFor("step 2", () => ext.ff.exists("#fp-colons, #preexisting-exception, #setup-secret-key"), 30_000);
  return ext;
}

test("https://localhost without an exception fails; the fingerprint is shown; with the exception it succeeds", async () => {
  const ext = await startSetup(a.setupText("t1", `https://localhost:${a.httpsPort}`));
  try {
    assert.equal(await ext.ff.text("#fp-colons"), fingerprint(a), "the colon form matches the certificate");
    const tabs = await ext.ff.handles();
    assert.equal(tabs.length, 3, "the server opened in a new tab");
    // Confirming before accepting the exception fails, keeps the tab, and lets the user retry.
    await ext.ff.switchTo(ext.ctl);
    await ext.ff.click("#cert-confirm");
    await waitFor("the failure", async () => (await ext.ff.js<string>("return document.getElementById('setup-2').innerText")).includes("still cannot reach"));
    assert.equal((await ext.ff.handles()).length, 3, "the server's tab stays open");
    // A tab the user closed is opened again.
    const serverTab = tabs.find((t) => t !== ext.web && t !== ext.ctl)!;
    await ext.ff.switchTo(serverTab);
    await ext.ff.cmd("DELETE", "/window");
    await ext.ff.switchTo(ext.ctl);
    await ext.ff.click("#cert-show-tab");
    await waitFor("the tab again", async () => (await ext.ff.handles()).length === 3);
    await ext.addException("localhost", a.httpsPort!, a.certPem());
    await ext.ff.switchTo(ext.ctl);
    await ext.ff.click("#cert-confirm");
    await waitFor("step 3", () => ext.ff.exists("#setup-secret-key"), 30_000);
    assert.equal((await ext.ff.handles()).length, 2, "the server tab closed");
  } finally {
    await ext.stop();
  }
});

test("https://127.0.0.1 with only the localhost exception fails", async () => {
  const ext = await startSetup(a.setupText("t2", `https://127.0.0.1:${a.httpsPort}`), {}, (e) => e.addException("localhost", a.httpsPort!, a.certPem()));
  try {
    assert.ok(await ext.ff.exists("#fp-colons"), "the test request failed, so the extension asks for an exception");
  } finally {
    await ext.stop();
  }
});

test("an exception stored for certificate A fails when the server presents certificate B", async () => {
  const ext = await startSetup(b.setupText("t3", `https://localhost:${b.httpsPort}`), {}, (e) => e.addException("localhost", b.httpsPort!, a.certPem()));
  try {
    assert.ok(await ext.ff.exists("#fp-colons"));
    assert.equal(await ext.ff.text("#fp-colons"), fingerprint(b));
  } finally {
    await ext.stop();
  }
});

test("an exception accepted before setup gets the warning that the fingerprint cannot be checked", async () => {
  const ext = await startSetup(a.setupText("t4", `https://localhost:${a.httpsPort}`), {}, (e) => e.addException("localhost", a.httpsPort!, a.certPem()));
  try {
    assert.match(await ext.ff.text("#preexisting-exception"), /cannot check the fingerprint/);
  } finally {
    await ext.stop();
  }
});

for (const httpsOnly of [false, true]) {
  test(`http://localhost and http://127.0.0.1 are not upgraded${httpsOnly ? ", with HTTPS-Only Mode" : ""}; headers are readable without CORS`, async () => {
    const ext = await startSetup(a.setupText(`t5${httpsOnly ? "h" : ""}`), httpsOnly ? { "dom.security.https_only_mode": true } : {});
    try {
      assert.ok(await ext.ff.exists("#setup-secret-key"), "a loopback http URL skips the certificate step");
      // The extension holds http://localhost/* now; grant http://127.0.0.1/* too, as setup with that URL would.
      await ext.grantOrigins(["http://127.0.0.1/*"]);
      for (const host of ["localhost", "127.0.0.1"]) {
        const r = await ext.inExtension<{ url: string; status: number; etag: string | null; date: string | null; cache: string | null }>(`
          const r = await fetch(arguments[0], { redirect: "error", credentials: "omit", cache: "no-store", headers: { Authorization: "Bearer x" } });
          return { url: r.url, status: r.status, etag: r.headers.get("ETag"), date: r.headers.get("Date"), cache: r.headers.get("Cache-Control") };`,
          `http://${host}:${a.httpPort}/v1/vault`);
        assert.equal(r.url, `http://${host}:${a.httpPort}/v1/vault`, "not upgraded to https");
        assert.equal(r.status, 401);
        assert.ok(r.date !== null && !Number.isNaN(Date.parse(r.date)), "the Date header is readable");
        assert.equal(r.cache, "no-store, no-transform");
      }
    } finally {
      await ext.stop();
    }
  });
}

void BASE;
