// End-to-end: sync between the extension and the CLI through a real vault serve, and the vault
// page's procedures: resolving a credential change made with the CLI, a new secret key with its
// kit, a new password, restore, recovery after an integrity error, and token repair. Needs
// vault-wasm; skipped with the WASM stub. The tests run in order and each builds on the last.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { Ext } from "./lib/ext.ts";
import { E2E_TIMING, sleep, waitFor } from "./lib/firefox.ts";
import { Cli, VaultServe, vaultBin } from "./lib/serve.ts";

const P1 = "correct horse battery staple e2e";
const P2 = "the cli changed it to this one";
const P3 = "a different long passphrase for e2e";

let serve: VaultServe;
let cli: Cli;
let ext: Ext;
let secretKey = "";

const names = async (text = "") => (await ext.request<{ name: string }[]>({ type: "list", text })).map((i) => i.name);
const pageText = () => ext.ff.js<string>("return document.body.innerText");

/**
 * Answers the vault page's prompts with `password` (and "Yes" to confirmations) until `done`
 * returns true.
 */
async function answerPrompts(password: string, done: () => Promise<boolean>, timeoutMs = 60_000, key?: string): Promise<string[]> {
  const deadline = Date.now() + timeoutMs;
  const seen: string[] = [];
  while (!(await done())) {
    if (Date.now() > deadline) throw new Error(`prompts did not finish:\n${await pageText()}`);
    if (await ext.ff.exists("#prompt")) seen.push(await ext.ff.text("#prompt"));
    if (await ext.ff.exists("#prompt-secret-key")) {
      if (key === undefined) throw new Error(`a secret key prompt the test did not expect:\n${await pageText()}`);
      await ext.ff.type("#prompt-password", password);
      await ext.ff.type("#prompt-secret-key", key);
      await ext.ff.click("#prompt-ok");
    } else if (await ext.ff.exists("#prompt-password")) {
      await ext.ff.type("#prompt-password", password);
      await ext.ff.click("#prompt-ok");
    } else if (await ext.ff.exists("#prompt-yes")) {
      await ext.ff.click("#prompt-yes");
    }
    await sleep(300);
  }
  return seen;
}

before(async () => {
  serve = await VaultServe.start();
  cli = new Cli(P1);
  secretKey = await cli.init(serve.setupText("cli"));
  const r = await cli.run(["add", "from-cli", "--username", "cli-user", "--uri", "https://cli.example", "--generate"]);
  assert.equal(r.code, 0, r.out);
  ext = await Ext.start();
  await ext.setup(serve.setupText("firefox"), secretKey, P1);
});

after(async () => {
  await ext?.stop();
  await serve?.stop();
  cli?.stop();
});

test("setup pulls the CLI's vault", async () => {
  const status = await ext.status();
  assert.equal(status.unlocked, true);
  assert.ok(status.summary?.generation !== null);
  assert.deepEqual(await names(), ["from-cli"]);
  const item = await ext.request<{ login: { username: string } }>({ type: "item", id: (await ext.request<{ id: string }[]>({ type: "list", text: "" }))[0].id });
  assert.equal(item.login.username, "cli-user");
});

test("a change in the extension syncs, and the CLI takes it", async () => {
  await ext.request({ type: "add", item: { type: "login", name: "from-firefox", username: "ff", password: "pw-ff", uris: [{ uri: "https://ff.example", match: "base_domain" }] } });
  await waitFor("push", async () => serve.requests("firefox").some((l) => l === "PUT /v1/vault 200"), 30_000);
  assert.equal((await ext.status()).summary?.unpushed, false);
  const r = await cli.run(["sync"]);
  assert.equal(r.code, 0, r.out);
  assert.match((await cli.run(["find", "from-firefox"])).out, /from-firefox/);
});

test("divergent changes in the CLI and the extension before either syncs are both kept", async () => {
  // The CLI works offline; the extension's change syncs at once.
  assert.equal((await cli.run(["--offline", "add", "offline-in-cli", "--generate"])).code, 0);
  await ext.request({ type: "add", item: { type: "note", name: "made in firefox meanwhile" } });
  await waitFor("pushed", async () => (await ext.status()).summary?.unpushed === false, 30_000);
  const r = await cli.run(["sync"]);
  assert.equal(r.code, 0, r.out);
  await ext.request({ type: "syncNow" });
  const all = await names();
  assert.ok(all.includes("offline-in-cli") && all.includes("made in firefox meanwhile"), all.join(", "));
  assert.match((await cli.run(["find", "made in firefox meanwhile"])).out, /made in firefox meanwhile/);
  for (const name of ["offline-in-cli", "made in firefox meanwhile"]) {
    await ext.request({ type: "remove", id: (await ext.request<{ id: string; name: string }[]>({ type: "list", text: name })).find((i) => i.name === name)!.id });
  }
  await ext.request({ type: "syncNow" });
  assert.equal((await cli.run(["sync"])).code, 0);
});

test("a change in the CLI reaches the extension on the next sync", async () => {
  assert.equal((await cli.run(["add", "second-from-cli", "--generate"])).code, 0);
  await ext.request({ type: "syncNow" });
  assert.deepEqual(await names(), ["from-cli", "from-firefox", "second-from-cli"]);
});

test("while unlocked, the idle check runs every minute and sync every 5 minutes", async () => {
  const alarms = await ext.alarms();
  // The end-to-end build checks for idleness every 3 s instead (src/shared/timing.ts).
  assert.equal(alarms.idle?.periodInMinutes, E2E_TIMING ? 0.05 : 1);
  assert.equal(alarms.sync?.periodInMinutes, 5);
});

test("the vault page's hold on the state lock makes the background script's commit wait", async () => {
  const stateBefore = (await ext.indexedDb()).state;
  // The control tab is a vault page: take the lock there and keep it.
  const held = await ext.inExtension<{ got: boolean; locks: unknown }>(`
    window.releaseLock = null;
    navigator.locks.request("vault-state", () => new Promise((r) => (window.releaseLock = r)));
    for (let i = 0; i < 500 && window.releaseLock === null; i++) await new Promise((r) => setTimeout(r, 10));
    return { got: window.releaseLock !== null, locks: await navigator.locks.query() };`);
  assert.ok(held.got, `the page could not take the lock: ${JSON.stringify(held.locks)}`);
  // Sent without waiting: WebDriver runs one command at a time, and this one waits on the lock.
  await ext.inExtension(`
    window.addReply = null;
    browser.runtime.sendMessage({ type: "add", item: { type: "note", name: "made under a held lock" } }).then((r) => (window.addReply = r));
    return true;`);
  // A negative check needs a window of time: the add is waiting on the lock, not slow.
  await sleep(1500);
  assert.equal(await ext.inExtension("return window.addReply;"), null, "the add has not finished");
  assert.equal((await ext.indexedDb()).state, stateBefore, "the background script did not write while the page held the lock");
  await ext.inExtension("window.releaseLock(); return true;");
  await waitFor("the add", async () => (await ext.inExtension<{ ok: boolean } | null>("return window.addReply;"))?.ok === true);
  assert.notEqual((await ext.indexedDb()).state, stateBefore);
  assert.ok((await names()).includes("made under a held lock"));
  await ext.request({ type: "remove", id: (await ext.request<{ id: string }[]>({ type: "list", text: "made under" }))[0].id });
});

test("unlock falls back to the local file when the server is unreachable", async () => {
  await ext.request({ type: "lock" });
  // Point the configuration at a closed port for this test only.
  const setPort = (port: number) => ext.inExtension<string>(`
    const db = await new Promise((ok, fail) => { const r = indexedDB.open("vault"); r.onsuccess = () => ok(r.result); r.onerror = () => fail(r.error); });
    const tx = db.transaction("kv", "readwrite"); const kv = tx.objectStore("kv");
    let url;
    const q = kv.get("config");
    q.onsuccess = () => { const u = new URL(q.result.url); u.port = String(arguments[0]); url = u.href; kv.put({ ...q.result, url }, "config"); };
    await new Promise((ok) => (tx.oncomplete = ok));
    return url;`, port);
  assert.match(await setPort(1), /:1\/$/);
  try {
    await ext.unlock(P1);
    assert.deepEqual(await names(), ["from-cli", "from-firefox", "second-from-cli"]);
  } finally {
    await setPort(serve.httpPort);
  }
});

test("a credential change made with the CLI stops background sync; the vault page resolves it", async () => {
  const r = await cli.run(["passwd"], [], 120_000, [P1, P2, P2]);
  assert.equal(r.code, 0, r.out);
  cli.password = P2;
  await ext.request({ type: "syncNow" });
  const stopped = (await ext.status()).summary?.stopped as { reason: string } | null;
  assert.equal(stopped?.reason, "credentials", "background sync never prompts, so it stops");
  const h = await ext.popup();
  await waitFor("stopped notice", () => ext.ff.exists("#stopped a"));
  assert.match(await ext.ff.text("#stopped"), /Resolve the credential change in the vault page/);
  await ext.closePopup(h);

  await ext.vaultPage("resolve");
  await ext.ff.clickWhenReady("#run-sync");
  await answerPrompts(P2, async () => (await pageText()).includes("Done."));
  const status = await ext.status();
  assert.equal(status.summary?.stopped, null);
  assert.equal(status.unlocked, true, "the new vault key went to storage.session");
  await ext.request({ type: "lock" });
  await ext.unlock(P2);
  assert.deepEqual(await names(), ["from-cli", "from-firefox", "second-from-cli"]);
});

test("a new secret key in the vault page shows the new kit, which must be confirmed", async () => {
  await ext.vaultPage("passwd");
  await waitFor("passwd section", () => ext.ff.exists("#passwd-change"));
  await ext.ff.js("const s = document.getElementById('passwd-change'); s.value = 'new-secret-key';");
  await ext.ff.click("#run-passwd");
  await answerPrompts(P2, () => ext.ff.exists("#kit-confirm"));
  const kit = await ext.ff.text("pre.kit");
  const newKey = kit.match(/VLT1-[0-9A-Z-]{39}/)![0];
  assert.notEqual(newKey, secretKey);
  assert.match(kit, new RegExp(`Server:\\s+http://localhost:${serve.httpPort}`));
  // A wrong last group is refused; the right one continues.
  await ext.ff.type("#kit-confirm", "ZZZZ");
  await ext.ff.click("#kit-ok");
  await waitFor("refusal", async () => (await pageText()).includes("not the last group"));
  await ext.ff.type("#kit-confirm", newKey.split("-").at(-1)!);
  await ext.ff.click("#kit-ok");
  await answerPrompts(P2, async () => (await pageText()).includes("The credentials are changed."));
  const status = await ext.status();
  assert.equal(status.summary?.pendingSecretKey, false, "the new key landed");
  assert.equal(status.summary?.stopped, null);
  await ext.request({ type: "lock" });
  await ext.unlock(P2);
});

test("a password change in the vault page; the new password unlocks", async () => {
  await ext.vaultPage("passwd");
  await ext.ff.clickWhenReady("#run-passwd");
  // vault-client asks for the current password, then the new one.
  await answerPrompts(P2, () => ext.ff.exists("#prompt-new-password"));
  await ext.ff.type("#prompt-new-password", P3);
  await ext.ff.type("#prompt-new-password-repeat", P3);
  await ext.ff.click("#prompt-ok");
  await answerPrompts(P2, async () => (await pageText()).includes("The credentials are changed."));
  await ext.request({ type: "lock" });
  await ext.unlock(P3);
  assert.deepEqual(await names(), ["from-cli", "from-firefox", "second-from-cli"]);
});

test("restore a revision from the vault page", async () => {
  await ext.vaultPage("restore");
  await ext.ff.clickWhenReady("#list-revisions");
  await waitFor("revisions", () => ext.ff.exists("#revisions li"));
  // The oldest revision is the CLI's first push, before any item existed.
  const count = await ext.ff.js<number>("return document.querySelectorAll('#revisions li').length");
  await ext.ff.js(`document.querySelectorAll('#revisions .restore-revision')[${count - 1}].click()`);
  // That revision is under the first password and the first secret key; vault-client tries the
  // stored secret key first and then asks for both.
  const prompts = await answerPrompts(P1, () => ext.ff.exists("#restore-confirm"), 60_000, secretKey);
  assert.ok(prompts.some((p) => p.includes("This revision is under an earlier secret key")), prompts.join("\n---\n"));
  assert.match(await pageText(), /removes 3 items/);
  await ext.ff.click("#restore-confirm");
  await waitFor("restored", async () => (await names()).length === 0, 30_000);
});

test("an integrity error stops sync, and recovery in the vault page repairs it", async () => {
  await ext.request({ type: "add", item: { type: "note", name: "before the damage", notes: "kept" } });
  await waitFor("pushed", async () => (await ext.status()).summary?.unpushed === false, 30_000);
  // A damaged copy of the current file under the same generation, pushed with a token of its own.
  const token = serve.setupText("tamper").match(/token=([0-9A-Z]+)/)![1];
  const url = `http://127.0.0.1:${serve.httpPort}/v1/vault`;
  const auth = { Authorization: `Bearer ${token}` };
  const current = await fetch(url, { headers: auth });
  const file = new Uint8Array(await current.arrayBuffer());
  file[file.length - 1] ^= 1;
  const put = await fetch(url, { method: "PUT", headers: { ...auth, "If-Match": current.headers.get("ETag")! }, body: file });
  assert.equal(put.status, 200);

  await ext.request({ type: "syncNow" });
  const stopped = (await ext.status()).summary?.stopped as { reason: string } | null;
  assert.equal(stopped?.reason, "integrity");
  await ext.vaultPage("resolve");
  await ext.ff.clickWhenReady("#run-recover");
  await answerPrompts(P3, async () => (await pageText()).includes("Recovery finished."));
  const status = await ext.status();
  assert.equal(status.summary?.stopped, null);
  assert.deepEqual(await names(), ["before the damage"]);
  await ext.request({ type: "syncNow" });
  assert.equal((await ext.status()).summary?.stopped, null, "sync runs again");
});

test("without the server's host permission, sync does not run and the popup says why", async () => {
  const origin = `http://localhost/*`;
  const before = serve.requests("firefox").length;
  assert.equal(await ext.inExtension("return browser.permissions.remove({ origins: [arguments[0]] });", origin), true);
  await ext.request({ type: "syncNow" });
  assert.equal((await ext.status()).syncIssue?.code, "host_permission");
  assert.equal(serve.requests("firefox").length, before, "no request reached the server");
  const h = await ext.popup();
  await waitFor("permission notice", () => ext.ff.exists("#sync-issue"));
  await ext.closePopup(h);
  await ext.grantOrigins([origin]);
  await ext.request({ type: "syncNow" });
  assert.equal((await ext.status()).syncIssue ?? null, null);
});

test("a revoked token stops sync, and the popup links to the vault page", async () => {
  execFileSync(vaultBin(), ["serve", "token", "rm", "firefox", "--data", join(serve.dir, "data")]);
  await ext.request({ type: "syncNow" });
  const status = await ext.status();
  assert.equal((status.summary?.stopped as { reason: string } | null)?.reason, "token");
  const h = await ext.popup();
  await waitFor("stopped notice", () => ext.ff.exists("#stopped a"));
  assert.match(await ext.ff.text("#stopped"), /Replace the server token in the vault page/);
  await ext.closePopup(h);
});

test("token repair: new setup text for the same server restarts sync", async () => {
  await ext.vaultPage("server");
  await waitFor("server section", () => ext.ff.exists("#server-setup-text"));
  await ext.ff.type("#server-setup-text", serve.setupText("firefox-2"));
  await ext.ff.click("#repair-token");
  await answerPrompts(P3, async () => (await pageText()).includes("The token is replaced."));
  await ext.request({ type: "syncNow" });
  const status = await ext.status();
  assert.equal(status.summary?.stopped, null);
  assert.ok(serve.requests("firefox-2").some((l) => l.startsWith("GET /v1/vault 200")), "the new token is used");
});
