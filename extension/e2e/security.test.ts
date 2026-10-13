// End-to-end: what web pages and content scripts can and cannot do (docs/firefox.md, Messages and
// Save offers), what the extension stores where (Storage), and a browser restart.

import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { isExtensionPage, isTopFrameContentScript, type Sender } from "../src/shared/messages.ts";
import { Ext } from "./lib/ext.ts";
import { ITEMS, PASSWORD, vault, type Fixture } from "./lib/fixture.ts";
import { BASE, EXTENSION_ID, waitFor } from "./lib/firefox.ts";

let f: Fixture;
let ext: Ext;
const profile = mkdtempSync(join(tmpdir(), "vault-e2e-profile-"));

before(async () => {
  f = await vault({ profile });
  ext = f.ext;
  await ext.grantOrigins(["*://*/*"]); // for the test content scripts
});

after(async () => {
  await f?.stop();
});

const fromContent = (msg: object, frame?: string) =>
  ext.contentScript<unknown>("(m) => browser.runtime.sendMessage(m)", [msg], frame);
const offers = async () => ((await ext.status()).offers ?? []) as { origin: string; username: string; action: string }[];
const origin = (host: string) => `http://${host}:${ext.pages.port}`;

/** Logs in on `host` as a person does: typing and clicking, which gives user activation. */
async function submitLogin(host: string, username: string, password: string): Promise<void> {
  await ext.open(host, "/login.html");
  await ext.ff.type("#user", username);
  await ext.ff.type("#pass", password);
  await ext.ff.click("#submit");
  await waitFor("signed in", () => ext.ff.exists("#done"));
}

test("content scripts get one constant reply and no effect, from the top frame or an iframe", async () => {
  await ext.setClipboard("before");
  await ext.open("www.example.com", "/subframe.html");
  const messages = [
    { type: "status" },
    { type: "unlock", password: PASSWORD },
    { type: "copy", id: f.ids.example, field: "password" },
    { type: "list", text: "" },
    { type: "lock" },
  ];
  for (const frame of [undefined, "frame.html"]) {
    for (const m of messages) assert.deepEqual(await fromContent(m, frame), {}, `${m.type} from ${frame ?? "the top frame"}`);
  }
  assert.deepEqual(await fromContent({ type: "saveSubmit", username: "iframe", password: "pw-iframe" }, "frame.html"), {});
  assert.equal((await ext.status()).unlocked, true, "lock had no effect");
  assert.equal(await ext.clipboard(), "before", "copy had no effect");
  assert.deepEqual(await offers(), [], "a subframe's submit is ignored");
  await ext.request({ type: "lock" });
  assert.deepEqual(await fromContent({ type: "unlock", password: PASSWORD }), {});
  assert.equal((await ext.status()).unlocked, false, "unlock had no effect");
  await ext.unlock(PASSWORD);
});

test("the real senders of the popup, the vault page, and a content script pass the right checks", async () => {
  await ext.inExtension(`
    window.senders = [];
    browser.runtime.onMessage.addListener((m, s) => { if (m.type === "probeSender") window.senders.push({ from: m.from, sender: JSON.parse(JSON.stringify(s)) }); });
    return true;`);
  const h = await ext.popup();
  await ext.ff.js("browser.runtime.sendMessage({ type: 'probeSender', from: 'popup' }).catch(() => {});");
  await ext.closePopup(h);
  const page = await ext.ff.newTab(`${BASE}page.html`);
  await ext.ff.js("browser.runtime.sendMessage({ type: 'probeSender', from: 'vault page' }).catch(() => {});");
  await ext.ff.cmd("DELETE", "/window");
  void page;
  await ext.open("www.example.com", "/login.html");
  await fromContent({ type: "probeSender", from: "content script" });
  const recorded = await waitFor("three senders", async () => {
    const s = await ext.inExtension<{ from: string; sender: Sender }[]>("return window.senders;");
    return s.length === 3 ? s : null;
  });
  const by = Object.fromEntries(recorded.map((r) => [r.from, r.sender]));
  assert.ok(isExtensionPage(by.popup, EXTENSION_ID, BASE), JSON.stringify(by.popup));
  assert.ok(isExtensionPage(by["vault page"], EXTENSION_ID, BASE), JSON.stringify(by["vault page"]));
  assert.ok(!isExtensionPage(by["content script"], EXTENSION_ID, BASE));
  assert.ok(isTopFrameContentScript(by["content script"], EXTENSION_ID));
  if (process.env.E2E_RECORD_SENDERS === "1") {
    writeFileSync(resolve(import.meta.dirname, "..", "test", "fixtures", "senders.json"),
      JSON.stringify({ id: EXTENSION_ID, base: BASE, senders: by }, null, 2) + "\n");
  }
});

test("a web page cannot load or open the extension's pages", async () => {
  await ext.open("www.example.com", "/login.html");
  const r = await ext.ff.jsAsync<{ fetch: string; script: string; url: string }>(`
    const done = arguments[arguments.length - 1];
    const url = arguments[0];
    const out = {};
    fetch(url + "popup.html").then(() => (out.fetch = "loaded"), () => (out.fetch = "refused")).then(() => {
      const s = document.createElement("script");
      s.src = url + "popup.js";
      s.onload = () => { out.script = "loaded"; next(); };
      s.onerror = () => { out.script = "refused"; next(); };
      document.head.append(s);
    });
    function next() {
      try { location.href = url + "popup.html"; } catch (e) {}
      setTimeout(() => { out.url = location.href; done(out); }, 1000);
    }`, BASE);
  assert.equal(r.fetch, "refused");
  assert.equal(r.script, "refused");
  assert.equal(r.url, origin("www.example.com") + "/login.html", "the page could not navigate to popup.html");
});

test("save offers: only a person's submit counts; a script's does not", async () => {
  await ext.vaultPage("offers");
  await ext.ff.clickWhenReady("#save-offers");
  await waitFor("watcher registered", async () =>
    (await ext.inExtension<number>("return (await browser.scripting.getRegisteredContentScripts({ ids: ['save-watcher'] })).length;")) === 1);
  await ext.open("o1.test", "/login.html");
  // No typing or clicking: the page has no user activation.
  await ext.ff.js(`
    const form = document.getElementById("form");
    document.getElementById("user").value = "script";
    document.getElementById("pass").value = "pw-script";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    form.requestSubmit();`);
  await waitFor("navigated", () => ext.ff.exists("#done"));
  await submitLogin("o2.test", "person", "pw-person");
  await waitFor("the person's offer", async () => (await offers()).some((o) => o.origin === origin("o2.test")));
  assert.equal((await offers()).some((o) => o.origin === origin("o1.test")), false, "the script's submits queued nothing");
});

test("offers: at most ten, one per origin, the newest replacing the oldest", async () => {
  for (let n = 3; n <= 12; n++) await submitLogin(`o${n}.test`, `user${n}`, `pw-${n}`);
  await waitFor("o12's offer", async () => (await offers()).some((o) => o.origin === origin("o12.test")));
  let list = await offers();
  assert.equal(list.length, 10);
  assert.equal(list.some((o) => o.origin === origin("o2.test")), false, "the oldest went");
  await submitLogin("o5.test", "again", "pw-again");
  await waitFor("o5 replaced", async () => (await offers()).find((o) => o.origin === origin("o5.test"))?.username === "again");
  list = await offers();
  assert.equal(list.length, 10);
  assert.equal(list.filter((o) => o.origin === origin("o5.test")).length, 1);
});

test("a submit in a subframe is ignored", async () => {
  await ext.request({ type: "offerDismiss", origin: origin("o3.test") });
  await ext.open("o3.test", "/subframe.html");
  await ext.ff.cmd("POST", "/frame", { id: { "element-6066-11e4-a52e-4f735466cecf": await ext.ff.find("#sub") } });
  await ext.ff.type("#f-user", "framed");
  await ext.ff.type("#f-pass", "pw-framed");
  await ext.ff.click("#f-submit");
  await ext.ff.cmd("POST", "/frame", { id: null });
  await ext.open("o4.test", "/login.html"); // a round trip through the background script
  assert.equal((await offers()).some((o) => o.origin === origin("o3.test")), false);
});

test("a lock clears the offers, and offers are dropped while locked", async () => {
  assert.ok((await offers()).length > 0);
  await ext.request({ type: "lock" });
  assert.equal((await ext.session()).offers, undefined);
  await submitLogin("o1.test", "while-locked", "pw-locked");
  await ext.unlock(PASSWORD);
  assert.deepEqual(await offers(), []);
});

test("storage.local holds settings only, and no key or password is stored in the clear", async () => {
  await ext.request({ type: "copy", id: f.ids.example, field: "password" });
  await submitLogin("o6.test", "stored", "pw-must-not-be-stored");
  await waitFor("offer", async () => (await offers()).some((o) => o.origin === origin("o6.test")));
  await ext.request({ type: "setSettings", settings: { idleMinutes: 15 } });

  const local = await ext.local();
  assert.deepEqual(Object.keys(local), ["settings"]);
  const vk = (await ext.session()).vk as string;
  assert.match(vk, /^[0-9a-f]{64}$/);
  const secrets = [vk, ...Object.values(ITEMS).map((i) => i.password), "pw-must-not-be-stored", PASSWORD];
  const dumps = JSON.stringify(await ext.indexedDb()) + JSON.stringify(local);
  for (const s of secrets) assert.equal(dumps.includes(s), false, `found ${s} through the APIs`);
  const hexOf = (s: string) => Buffer.from(s).toString("hex");
  for (const s of secrets.slice(1)) assert.equal(dumps.includes(hexOf(s)), false, `found ${s} as hex`);

  // The files of the profile's storage, as a person with disk access would read them.
  const files: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else files.push(p);
    }
  };
  walk(join(ext.ff.profile, "storage"));
  assert.ok(files.some((p) => p.includes("moz-extension")), "the extension's storage is on disk");
  const vkBytes = Buffer.from(vk, "hex");
  for (const p of files) {
    const bytes = readFileSync(p);
    assert.equal(bytes.includes(vkBytes), false, `the vault key's bytes in ${p}`);
    for (const s of secrets) {
      assert.equal(bytes.includes(Buffer.from(s, "utf8")), false, `${s} in ${p}`);
      assert.equal(bytes.includes(Buffer.from(s, "utf16le")), false, `${s} (UTF-16) in ${p}`);
    }
  }
});

test("a browser restart on the same profile starts locked, with the state intact", async () => {
  const pages = ext.pages;
  const before = (await ext.request<{ name: string }[]>({ type: "list", text: "" })).map((i) => i.name);
  await ext.stop(true);
  ext = await Ext.start({}, { profile, pages });
  f.ext = ext;
  const status = await ext.status();
  assert.equal(status.configured, true);
  assert.equal(status.unlocked, false);
  assert.deepEqual(await ext.session(), {}, "storage.session is empty after the restart");
  await ext.unlock(PASSWORD);
  assert.deepEqual((await ext.request<{ name: string }[]>({ type: "list", text: "" })).map((i) => i.name), before);
});
