// End-to-end: the idle lock and what a lock leaves behind (docs/firefox.md, Background script), the
// clipboard clear, and the vault page's own session when the vault locks. The build has the
// end-to-end timings (src/shared/timing.ts): the idle check every 3 s and the clipboard clear after
// 6 s.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { PASSWORD, vault, type Fixture } from "./lib/fixture.ts";
import { E2E_TIMING, waitFor } from "./lib/firefox.ts";

let f: Fixture;
const ext = () => f.ext;
const MINUTE = 60_000;

before(async () => {
  assert.ok(E2E_TIMING, "npm run e2e builds dist/ with VAULT_E2E_TIMING=1");
  f = await vault();
  await ext().grantOrigins(["*://*/*"]); // for the test content scripts
});

after(async () => {
  await f?.stop();
});

/** Sends `msg` from a content script in the web tab's top frame. */
const fromContent = (msg: object) => ext().contentScript<unknown>("(m) => browser.runtime.sendMessage(m)", [msg]);

async function ensureUnlocked(): Promise<void> {
  if (!(await ext().status()).unlocked) await ext().unlock(PASSWORD);
}

test("the event page really unloads, and a new instance starts on the next event", async () => {
  await ensureUnlocked();
  await ext().terminateBackground();
  assert.equal(await ext().backgroundState(), "stopped");
  assert.equal((await ext().status()).unlocked, true, "an unload alone does not lock");
  assert.equal(await ext().backgroundState(), "running");
});

test("idle lock from the alarm alone, with no request, after an unload", async () => {
  await ensureUnlocked();
  assert.ok((await ext().alarms()).idle, "the idle alarm runs while unlocked");
  await ext().setLastActivity(Date.now() - 16 * MINUTE);
  await ext().terminateBackground();
  // Only storage is read from here on, which does not wake the background script.
  await waitFor("the alarm locks", async () => (await ext().session()).vk === undefined, 30_000);
  assert.equal((await ext().session()).lastActivity, undefined);
});

test("idle lock at the start of a new instance, woken by a content script message", async () => {
  await ensureUnlocked();
  await ext().inExtension("await browser.alarms.clear('idle'); return true;");
  await ext().setLastActivity(Date.now() - 16 * MINUTE);
  await ext().terminateBackground();
  await ext().open("www.example.com", "/login.html");
  assert.deepEqual(await fromContent({ type: "saveSubmit", username: "x", password: "y" }), {});
  await waitFor("the start check locks", async () => (await ext().session()).vk === undefined, 15_000);
});

test("only user actions count as activity", async () => {
  await ensureUnlocked();
  await ext().open("www.example.com", "/login.html");
  const before = Date.now() - MINUTE;
  for (const [what, act] of [
    ["status", () => ext().request({ type: "status" })],
    ["syncNow", () => ext().request({ type: "syncNow" })],
    ["a content script message", () => fromContent({ type: "status" })],
    ["a save watcher message", () => fromContent({ type: "saveSubmit", username: "u", password: "p" })],
  ] as const) {
    await ext().setLastActivity(before);
    await act();
    assert.equal(await ext().lastActivity(), before, `${what} is not activity`);
  }
  await ext().setLastActivity(before);
  await ext().shortcut();
  await waitFor("the shortcut counts", async () => ((await ext().lastActivity()) ?? 0) > before);
  await ext().setLastActivity(before);
  await ext().contextMenu("#user", "Fill login from vault");
  await waitFor("the menu counts", async () => ((await ext().lastActivity()) ?? 0) > before);
});

test("a lock leaves no key, offers, or activity, keeps the clipboard clear, and refuses everything", async () => {
  await ensureUnlocked();
  await ext().open("www.example.com", "/signup.html");
  await ext().contextMenu("#new", "Generate password with vault"); // records an offer
  await waitFor("offer", async () => ((await ext().session()).offers as unknown[] | undefined)?.length === 1);
  await ext().request({ type: "copy", id: f.ids.example, field: "password" });
  await ext().request({ type: "lock" });
  const session = await ext().session();
  assert.equal(session.vk, undefined);
  assert.equal(session.offers, undefined);
  assert.equal(session.lastActivity, undefined);
  assert.equal(typeof session.clipHash, "string", "the clipboard clear still knows what to clear");
  const alarms = await ext().alarms();
  assert.equal(alarms.idle, undefined);
  assert.equal(alarms.sync, undefined);
  for (const request of [
    { type: "fill", id: f.ids.example, confirmedHost: null },
    { type: "copy", id: f.ids.example, field: "password" },
    { type: "update", id: f.ids.example, base: {}, edited: {} },
    { type: "list", text: "" },
  ]) {
    await assert.rejects(ext().request(request), /^Error: locked:/, request.type);
  }
  await ext().open("www.example.com", "/login.html");
  await ext().shortcut();
  await waitFor("badge !", async () => (await ext().badge()) === "!");
  await waitFor("copy then lock still clears the clipboard", async () => (await ext().clipboard()) === "", 15_000);
});

test("clipboard: a value the user replaced is not cleared; of two copies, the last is cleared", async () => {
  await ensureUnlocked();
  await ext().request({ type: "copy", id: f.ids.example, field: "password" });
  assert.equal(await ext().clipboard(), "pw-example");
  await ext().setClipboard("something the user copied");
  await waitFor("the clear ran", async () => (await ext().session()).clipHash === undefined, 15_000);
  assert.equal(await ext().clipboard(), "something the user copied");

  await ext().request({ type: "copy", id: f.ids.example, field: "username" });
  await ext().request({ type: "copy", id: f.ids.example, field: "password" });
  assert.equal(await ext().clipboard(), "pw-example");
  await waitFor("cleared", async () => (await ext().clipboard()) === "", 15_000);
});

test("a lock from the popup kills the vault page's restore session, and the restore refuses", async () => {
  await ensureUnlocked();
  const names = async () => (await ext().request<{ name: string }[]>({ type: "list", text: "" })).map((i) => i.name);
  const before = await names();
  await ext().vaultPage("restore");
  await ext().ff.clickWhenReady("#list-revisions");
  await waitFor("revisions", () => ext().ff.exists("#revisions li"));
  const count = await ext().ff.js<number>("return document.querySelectorAll('#revisions li').length");
  await ext().ff.js(`document.querySelectorAll('#revisions .restore-revision')[${count - 1}].click()`);
  await waitFor("preview or prompt", async () => {
    if (await ext().ff.exists("#prompt-password")) {
      await ext().ff.type("#prompt-password", PASSWORD);
      await ext().ff.click("#prompt-ok");
    }
    return ext().ff.exists("#restore-confirm");
  }, 30_000);

  const h = await ext().popup();
  await ext().ff.click("#lock");
  await waitFor("locked popup", () => ext().ff.exists("#password"));
  await ext().closePopup(h);

  await ext().ff.switchTo(ext().ctl);
  await waitFor("the page closed its session", () => ext().ff.exists("#page-locked"));
  await ext().ff.click("#restore-confirm");
  await waitFor("refused", async () => /locked/.test(await ext().ff.js<string>("return document.getElementById('restore').innerText")));
  await ext().unlock(PASSWORD);
  assert.deepEqual(await names(), before, "nothing was restored");
});
