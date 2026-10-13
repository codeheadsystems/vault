// End-to-end: unlock, add and edit in the popup, and every fill path (docs/firefox.md, Fill),
// against a real vault serve with a vault the CLI created.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { ITEMS, PASSWORD, vault, type Fixture } from "./lib/fixture.ts";
import { BASE, waitFor } from "./lib/firefox.ts";

let f: Fixture;
const ext = () => f.ext;

before(async () => {
  f = await vault();
});

after(async () => {
  await f?.stop();
});

/** The value of a field in the web tab (in iframe `frame` when given). */
const value = (css: string, frame?: string) => ext().fieldValue(css, frame);

test("unlock through the popup, and a wrong master password is refused", async () => {
  assert.equal((await ext().status()).unlocked, true, "setup leaves the vault unlocked");
  await ext().request({ type: "lock" });
  const h = await ext().popup();
  await ext().ff.type("#password", "not the password");
  await ext().ff.click("#unlock");
  await waitFor("error", async () => (await ext().ff.text(".flash.error")).includes("Wrong master password"));
  await ext().closePopup(h);
  await ext().unlock(PASSWORD);
  assert.equal((await ext().status()).unlocked, true);
});

test("add a login in the popup", async () => {
  const h = await ext().popup();
  await ext().ff.click("#add");
  await waitFor("add form", () => ext().ff.exists("#edit-form"));
  await ext().ff.type("#edit-name", "added in popup");
  await ext().ff.type("#edit-username", "pat");
  await ext().ff.type("#edit-password", "pw-pat");
  await ext().ff.type("#edit-uri", "https://popup.example");
  await ext().ff.click("#edit-save");
  await waitFor("item in the list", async () => (await ext().ff.text("#results")).includes("added in popup"));
  await ext().closePopup(h);
  const [entry] = await ext().request<{ id: string; username: string; uris: string[] }[]>({ type: "list", text: "added in popup" });
  assert.equal(entry.username, "pat");
  assert.deepEqual(entry.uris, ["https://popup.example"]);
});

test("quick edit in the popup masks the password and keeps the fields it does not show", async () => {
  const h = await ext().popup();
  await ext().ff.type("#search", "nas");
  await ext().ff.clickWhenReady(`#results li[data-id="${f.ids.nas}"] a`);
  await ext().ff.clickWhenReady("#item-edit");
  await waitFor("edit form", () => ext().ff.exists("#edit-form"));
  assert.equal(await ext().ff.js("return document.getElementById('edit-password').type"), "password");
  await ext().ff.click("#edit-reveal");
  assert.equal(await ext().ff.js("return document.getElementById('edit-password').type"), "text");
  await ext().ff.type("#edit-username", "root");
  await ext().ff.click("#edit-save");
  await waitFor("list again", () => ext().ff.exists("#search"));
  await ext().closePopup(h);
  const item = await ext().request<{ login: { username: string; password: string; uris: unknown } }>({ type: "item", id: f.ids.nas });
  assert.equal(item.login.username, "root");
  assert.equal(item.login.password, "pw-nas");
  assert.deepEqual(item.login.uris, ITEMS.nas.uris);
  await ext().request({ type: "update", id: f.ids.nas, base: item, edited: { ...item, login: { ...item.login, username: "admin" } } });
});

test("popup fill: the top frame and same-origin frames only", async () => {
  await ext().open("www.example.com", "/frames.html");
  const h = await ext().popup();
  await waitFor("candidates", () => ext().ff.exists(`#page-candidates li[data-id="${f.ids.example}"]`));
  assert.equal(await ext().ff.exists(`#page-candidates li[data-id="${f.ids.secure}"]`), false, "an https item never fills an http page of a public host");
  await ext().ff.click(`#page-candidates li[data-id="${f.ids.example}"] .fill`);
  await waitFor("top frame filled", async () => (await value("#pass")) === "pw-example");
  await ext().closePopup(h);
  assert.equal(await value("#user"), "ann");
  assert.equal(await value("#f-pass", "#same"), "pw-example");
  assert.equal(await value("#f-pass", "#nav"), "pw-example");
  assert.equal(await value("#f-pass", "#site"), "", "same-site but cross-origin");
  assert.equal(await value("#f-pass", "#xsite"), "", "cross-site");
});

test("shortcut: one fill candidate fills, after a frame navigated", async () => {
  await ext().open("www.example.com", "/frames.html");
  await ext().ff.js(`document.getElementById("same").src = "/frame2.html";
                     document.getElementById("nav").src = "http://login.example.com:" + location.port + "/frame2.html";`);
  await waitFor("frames navigated", async () => (await ext().ff.js<string>(
    "return document.getElementById('same').contentDocument?.querySelector('#f2-pass') ? 'yes' : ''")) === "yes");
  await ext().shortcut();
  await waitFor("top frame filled", async () => (await value("#pass")) === "pw-example");
  assert.equal(await value("#f2-pass", "#same"), "pw-example", "a same-origin frame's new document is filled");
  assert.equal(await value("#f2-pass", "#nav"), "", "a frame that navigated to another origin is not");
  assert.equal(await ext().badge(), "");
});

test("fields a person cannot see get nothing; the visible form is filled", async () => {
  await ext().open("www.example.com", "/decoy.html");
  await ext().shortcut();
  await waitFor("real form filled", async () => (await value("#pass")) === "pw-example");
  assert.equal(await value("#user"), "ann");
  for (const id of ["decoy-user", "decoy-pass", "decoy-tiny", "decoy-clipped", "decoy-covered"]) {
    assert.equal(await value(`#${id}`), "", id);
  }
});

test("srcdoc, about:blank, data:, and sandboxed frames are not filled", async () => {
  await ext().open("frames.test", "/frames2.html");
  await ext().shortcut();
  await waitFor("top frame filled", async () => (await value("#pass")) === "pw-frames");
  assert.equal(await value("#s-pass", "#srcdoc"), "", "srcdoc");
  assert.equal(await value("#b-pass", "#blank"), "", "about:blank");
  assert.equal(await value("#d-pass", "#data"), "", "data:");
  assert.equal(await value("#f-pass", "#sandboxed"), "", "sandboxed");
});

test("shortcut: two candidates set the badge, and the popup picks one", async () => {
  await ext().open("other.test", "/login.html");
  await ext().shortcut();
  await waitFor("badge 2", async () => (await ext().badge()) === "2");
  assert.equal(await value("#pass"), "");
  const h = await ext().popup();
  await waitFor("both candidates", async () => (await ext().ff.text("#page-candidates")).includes("other two"));
  await ext().ff.click(`#page-candidates li[data-id="${f.ids.other2}"] .fill`);
  await waitFor("filled", async () => (await value("#pass")) === "pw-o2");
  await ext().closePopup(h);
  assert.equal(await ext().badge(), "");
});

test("two normal windows: the shortcut fills the focused window's tab only", async () => {
  await ext().open("www.example.com", "/login.html");
  const second = await ext().newWindow(ext().pages.url("frames.test", "/login.html"));
  await ext().ff.chrome(
    `const done = arguments[arguments.length - 1];
     const win = Services.wm.getMostRecentWindow("navigator:browser");
     win.document.querySelector('[id^="ext-keyset-id-"] key').doCommand();
     done(true);`);
  await waitFor("second window filled", async () => (await ext().ff.value("#pass")) === "pw-frames");
  await ext().ff.cmd("DELETE", "/window");
  assert.equal(await value("#pass"), "", "the other window's page is untouched");
  void second;
});

test("a tab switched between the shortcut and the pick: the popup offers the new tab's logins", async () => {
  await ext().open("other.test", "/login.html");
  await ext().shortcut();
  await waitFor("badge 2", async () => (await ext().badge()) === "2");
  const first = ext().web;
  ext().web = await ext().ff.newTab(ext().pages.url("www.example.com", "/login.html"));
  try {
    const h = await ext().popup();
    await waitFor("candidates", () => ext().ff.exists(`#page-candidates li[data-id="${f.ids.example}"]`));
    assert.equal(await ext().ff.exists(`#page-candidates li[data-id="${f.ids.other1}"]`), false);
    await ext().ff.click(`#page-candidates li[data-id="${f.ids.example}"] .fill`);
    await waitFor("filled", async () => (await value("#pass")) === "pw-example");
    await ext().closePopup(h);
  } finally {
    await ext().ff.switchTo(ext().web);
    await ext().ff.cmd("DELETE", "/window");
    ext().web = first;
  }
  assert.equal(await value("#pass"), "", "the first tab is untouched");
});

test("non-web tabs: the shortcut does nothing, and a popup fill is refused", async () => {
  for (const url of ["about:blank", `${BASE}page.html`]) {
    await ext().ff.switchTo(ext().web);
    await ext().ff.nav(url);
    await ext().shortcut();
    assert.notEqual(await ext().badge(), "1");
    const r = await ext().request<{ kind: string; reason?: string }>({ type: "fill", id: f.ids.example, confirmedHost: null });
    assert.deepEqual(r, { kind: "nothing", reason: "not_a_web_page" }, url);
  }
});

test("an item that is not a candidate: refused on a public http page, asked on a local host", async () => {
  // www.example.com over http is not a local host: no override, whatever the user would confirm.
  await ext().open("www.example.com", "/login.html");
  await ext().grantActiveTab(); // as opening the popup does
  const refused = await ext().request<{ kind: string }>({ type: "fill", id: f.ids.other1, confirmedHost: `www.example.com:${ext().pages.port}` });
  assert.equal(refused.kind, "refused");
  // nas.lan over http is a local host: the popup asks, naming it.
  await ext().open("nas.lan", "/login.html");
  const h = await ext().popup();
  await ext().ff.type("#search", "other one");
  await ext().ff.clickWhenReady(`#results li[data-id="${f.ids.other1}"] a`);
  await ext().ff.clickWhenReady("#item-fill");
  await waitFor("confirmation", () => ext().ff.exists("#confirm"));
  assert.match(await ext().ff.text("#confirm"), new RegExp(`not saved for nas\\.lan:${ext().pages.port}`));
  await ext().ff.click("#confirm-no");
  await ext().closePopup(h);
  assert.equal(await value("#pass"), "", "nothing filled after Cancel");
});

test("a confirmation for one page does not carry to another after a navigation", async () => {
  /** Asks about nas.lan, navigates the tab to other.test, then answers yes to the old question. */
  const answerStale = async () => {
    await ext().open("nas.lan", "/login.html");
    const h = await ext().popup();
    await ext().ff.clickWhenReady(`#page-candidates li[data-id="${f.ids.nas}"] .fill`);
    await waitFor("confirmation", () => ext().ff.exists("#confirm"));
    assert.match(await ext().ff.text("#confirm"), /nas\.lan/);
    await ext().open("other.test", "/login.html");
    await ext().ff.switchTo(h);
    await ext().ff.click("#confirm-yes");
    return h;
  };
  // With activeTab only, the navigation ends the grant: the background cannot read the new page,
  // and nothing is filled.
  let h = await answerStale();
  await waitFor("refusal", async () => (await ext().ff.text("#app")).includes("address is not available"));
  await ext().closePopup(h);
  assert.equal(await value("#pass"), "");
  // With the all-sites permission it can, and it asks again about the new page.
  await ext().grantOrigins(["*://*/*"]);
  try {
    h = await answerStale();
    await waitFor("asked again", async () => (await ext().ff.text("#confirm")).includes("other.test"));
    await ext().closePopup(h);
    assert.equal(await value("#pass"), "", "nothing filled");
  } finally {
    await ext().inExtension("return browser.permissions.remove({ origins: ['*://*/*'] });");
  }
});

test("a top-frame navigation between the candidate lookup and the pick fills nothing", async () => {
  await ext().open("other.test", "/login.html");
  await ext().shortcut();
  await waitFor("badge 2", async () => (await ext().badge()) === "2");
  // The tab goes to another site before the user picks one of other.test's logins, in a popup
  // opened on the new page.
  await ext().open("www.example.com", "/login.html");
  await ext().grantActiveTab();
  const r = await ext().request<{ kind: string }>({ type: "fill", id: f.ids.other2, confirmedHost: null });
  assert.equal(r.kind, "refused");
  assert.equal(await value("#pass"), "");
});

test("local host over http: the shortcut does not fill, the popup asks, then fills", async () => {
  await ext().open("nas.lan", "/login.html");
  await ext().shortcut();
  await waitFor("badge 1", async () => (await ext().badge()) === "1");
  assert.equal(await value("#pass"), "");
  const h = await ext().popup();
  await ext().ff.clickWhenReady(`#page-candidates li[data-id="${f.ids.nas}"] .fill`);
  await waitFor("confirmation", () => ext().ff.exists("#confirm"));
  assert.match(await ext().ff.text("#confirm"), /served over http/);
  await ext().ff.click("#confirm-yes");
  await waitFor("filled", async () => (await value("#pass")) === "pw-nas");
  await ext().closePopup(h);
});

test("context menu fill", async () => {
  await ext().open("www.example.com", "/login.html");
  await ext().contextMenu("#user", "Fill login from vault");
  await waitFor("filled", async () => (await value("#pass")) === "pw-example");
  assert.equal(await value("#user"), "ann");
});

test("generate into a field records a save offer", async () => {
  await ext().open("www.example.com", "/signup.html");
  await ext().contextMenu("#new", "Generate password with vault");
  const generated = await waitFor("generated password", async () => (await value("#new")) || null);
  assert.equal(await value("#again"), generated);
  assert.ok(generated.length >= 20);
  const origin = `http://www.example.com:${ext().pages.port}`;
  assert.ok((await ext().status()).offers?.some((o) => o.origin === origin));
  await ext().request({ type: "offerDismiss", origin });
});

test("with the all-sites permission, the selection still keeps the fill to the top frame's origin", async () => {
  await ext().grantOrigins(["*://*/*"]);
  await ext().open("www.example.com", "/frames.html");
  await ext().shortcut();
  await waitFor("top frame filled", async () => (await value("#pass")) === "pw-example");
  assert.equal(await value("#f-pass", "#same"), "pw-example");
  assert.equal(await value("#f-pass", "#site"), "", "same-site but cross-origin");
  assert.equal(await value("#f-pass", "#xsite"), "", "cross-site");
});
