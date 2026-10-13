// The extension under test: a Firefox session with the extension installed, a page server, a
// control tab (the vault page, an extension page with the `browser` API), and helpers that act as
// the user does.

import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { BASE, EXTENSION_ID, Firefox, waitFor } from "./firefox.ts";
import { HOSTS, Pages } from "./pages.ts";

const KEYSET = `#ext-keyset-id-${EXTENSION_ID.replace(/[^a-z0-9]/gi, "_")}`;
const WIDGET = `${EXTENSION_ID.replace(/[^a-z0-9]/gi, "_")}-browser-action`;

export interface Status {
  configured: boolean;
  unlocked: boolean;
  summary?: { unpushed: boolean; generation: number | null; stopped: unknown; lastSync: number | null; pendingSecretKey: boolean };
  syncIssue?: { code: string } | null;
  offers?: { origin: string; username: string; action: string; name: string }[];
}

export class Ext {
  ff: Firefox;
  pages: Pages;
  /** The tab with the web page under test, in the first window. */
  web = "";
  /** The control tab: the vault page, in a popup-type window, so that the web tab's window is the
   * only normal window and so the target of every fill, as in real use. */
  ctl = "";

  private constructor(ff: Firefox, pages: Pages) {
    this.ff = ff;
    this.pages = pages;
  }

  static async start(prefs: Record<string, unknown> = {}, options: { profile?: string; pages?: Pages } = {}): Promise<Ext> {
    const pages = options.pages ?? (await Pages.start());
    const ff = await Firefox.start({ "network.dns.localDomains": HOSTS.join(","), ...prefs }, { profile: options.profile });
    const ext = new Ext(ff, pages);
    ext.web = await ff.handle();
    await ff.installExtension();
    await waitFor("the background script", async () => (await ext.backgroundState()) === "running");
    await ff.nav(BASE + "page.html");
    const before = await ff.handles();
    await ff.jsAsync("const done = arguments[0]; browser.windows.create({ type: 'popup', url: 'page.html', width: 900, height: 900 }).then(() => done(true));");
    ext.ctl = await waitFor("control window", async () => (await ff.handles()).find((h) => !before.includes(h)));
    await ff.nav("about:blank");
    await ff.switchTo(ext.ctl);
    return ext;
  }

  async stop(keepPages = false): Promise<void> {
    await this.ff.quit();
    if (!keepPages) await this.pages.stop();
  }

  /** Ends the event page now, as Firefox does after it has been idle, and waits until it stopped. */
  async terminateBackground(): Promise<void> {
    await this.ff.chrome(
      `const done = arguments[arguments.length - 1];
       const ext = WebExtensionPolicy.getByID(arguments[0]).extension;
       ext.terminateBackground({ disableResetIdleForTest: true }).then(() => done(ext.backgroundState), (e) => done(String(e)));`,
      EXTENSION_ID);
    await waitFor("background stopped", async () => (await this.backgroundState()) === "stopped");
  }

  /** "starting", "running", "suspending", or "stopped". */
  backgroundState(): Promise<string> {
    return this.ff.chrome<string>(
      `const done = arguments[arguments.length - 1];
       done(WebExtensionPolicy.getByID(arguments[0]).extension.backgroundState);`, EXTENSION_ID);
  }

  /** storage.session, read from the control tab, which does not wake the background script. */
  session(): Promise<Record<string, unknown>> {
    return this.inExtension("return browser.storage.session.get(null);");
  }

  /** storage.local, read from the control tab. */
  local(): Promise<Record<string, unknown>> {
    return this.inExtension("return browser.storage.local.get(null);");
  }

  /** Every IndexedDB record of the extension, with byte arrays as hex. */
  indexedDb(): Promise<Record<string, unknown>> {
    return this.inExtension(`
      const db = await new Promise((ok, fail) => { const r = indexedDB.open("vault"); r.onsuccess = () => ok(r.result); r.onerror = () => fail(r.error); });
      const kv = db.transaction("kv").objectStore("kv");
      const [keys, values] = await Promise.all([kv.getAllKeys(), kv.getAll()].map((q) => new Promise((ok) => (q.onsuccess = () => ok(q.result)))));
      const hex = (v) => v instanceof Uint8Array ? Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("")
        : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, hex(x)])) : v;
      db.close();
      return Object.fromEntries(keys.map((k, i) => [k, hex(values[i])]));`);
  }

  /** The extension's alarms, by name. */
  async alarms(): Promise<Record<string, { periodInMinutes?: number }>> {
    const list = await this.inExtension<{ name: string; periodInMinutes?: number }[]>("return browser.alarms.getAll();");
    return Object.fromEntries(list.map((a) => [a.name, a]));
  }

  async setLastActivity(ms: number): Promise<void> {
    await this.inExtension("await browser.storage.session.set({ lastActivity: arguments[0] }); return true;", ms);
  }

  async lastActivity(): Promise<number | null> {
    return ((await this.session()).lastActivity as number | undefined) ?? null;
  }

  /** The extension's ID for the tab WebDriver has selected in `handle`. */
  async tabId(handle = this.web): Promise<number> {
    await this.ff.switchTo(handle);
    return this.ff.chrome<number>(
      `const done = arguments[arguments.length - 1];
       const ext = WebExtensionPolicy.getByID(arguments[0]).extension;
       const win = Services.wm.getMostRecentWindow("navigator:browser");
       done(ext.tabManager.getWrapper(win.gBrowser.selectedTab).id);`, EXTENSION_ID);
  }

  /**
   * Runs `func` (source text) as one of the extension's content scripts in the web tab, in the top
   * frame or in the subframes whose URL path is `frame`, and returns its result. Needs a host
   * permission for the page (grantOrigins).
   */
  async contentScript<T>(func: string, args: unknown[] = [], frame?: string): Promise<T> {
    const tabId = await this.tabId();
    return this.inExtension<T>(`
      const [tabId, args, frame] = arguments;
      let frameIds = [0];
      if (frame) {
        const frames = await browser.webNavigation.getAllFrames({ tabId });
        frameIds = frames.filter((f) => f.frameId !== 0 && new URL(f.url).pathname === "/" + frame).map((f) => f.frameId);
        if (frameIds.length === 0) throw new Error("no subframe " + frame);
      }
      const [r] = await browser.scripting.executeScript({ target: { tabId, frameIds }, func: ${func}, args });
      return r.error ? { error: String(r.error) } : r.result;`, tabId, args, frame ?? null);
  }

  /** Opens `url` in a new normal window; returns its handle. */
  async newWindow(url: string): Promise<string> {
    const { handle } = (await this.ff.cmd("POST", "/window/new", { type: "window" })) as { handle: string };
    await this.ff.switchTo(handle);
    await this.ff.nav(url);
    return handle;
  }

  /** Runs `script` in the control tab, where `browser` is the extension's API. */
  async inExtension<T>(script: string, ...args: unknown[]): Promise<T> {
    await this.ff.switchTo(this.ctl);
    return this.ff.jsAsync<T>(
      `const done = arguments[arguments.length - 1];
       (async () => { ${script} })().then(done, (e) => done({ error: String(e) }));`,
      ...args,
    );
  }

  /** A request to the background script, from the control tab. */
  async request<T = unknown>(request: object): Promise<T> {
    const r = await this.inExtension<{ ok: boolean; value?: T; code?: string; message?: string }>(
      "return browser.runtime.sendMessage(arguments[0]);", request);
    if (!r.ok) throw new Error(`${r.code}: ${r.message}`);
    return r.value as T;
  }

  status(): Promise<Status> {
    return this.request<Status>({ type: "status" });
  }

  /** Opens `path` on `host` in the web tab and makes it the active tab of its window. */
  async open(host: string, path: string, scheme = "http"): Promise<void> {
    await this.ff.switchTo(this.web);
    await this.ff.nav(this.pages.url(host, path, scheme));
  }

  /** Opens the vault page at `section`, reloading it. */
  async vaultPage(section = ""): Promise<void> {
    await this.ff.switchTo(this.ctl);
    await this.ff.nav(`${BASE}page.html?${Date.now()}${section ? `#${section}` : ""}`);
  }

  /** Sets up the extension in the vault page with the setup text, secret key, and password. */
  async setup(setupText: string, secretKey: string, password: string): Promise<void> {
    await this.ff.switchTo(this.ctl);
    await this.ff.nav(BASE + "page.html#setup");
    await waitFor("setup form", () => this.ff.exists("#setup-text"));
    await this.ff.type("#setup-text", setupText);
    await this.ff.click("#setup-continue");
    await waitFor("secret key field", () => this.ff.exists("#setup-secret-key"), 30_000);
    await this.ff.type("#setup-secret-key", secretKey);
    await this.ff.type("#setup-password", password);
    await this.ff.click("#setup-finish");
    await waitFor("setup to finish", () => this.ff.exists("#setup-done"), 60_000);
  }

  /** Grants activeTab on the web tab, as a click on the toolbar button does. */
  async grantActiveTab(): Promise<void> {
    await this.ff.switchTo(this.web);
    await this.ff.chrome(
      `const done = arguments[arguments.length - 1];
       const win = Services.wm.getMostRecentWindow("navigator:browser");
       const ext = WebExtensionPolicy.getByID(arguments[0]).extension;
       ext.tabManager.addActiveTabPermission(win.gBrowser.selectedTab);
       done(true);`, EXTENSION_ID);
  }

  /**
   * Opens the popup, as the toolbar button does: activeTab on the web tab, then popup.html. The
   * popup opens in a popup-type window, which the background script never takes as the target
   * tab. Returns with WebDriver in the popup.
   */
  async popup(): Promise<string> {
    await this.ff.switchTo(this.ctl);
    const before = await this.ff.handles();
    await this.ff.jsAsync("const done = arguments[0]; browser.windows.create({ type: 'popup', url: 'popup.html', width: 400, height: 600 }).then(() => done(true));");
    const handle = await waitFor("popup window", async () => (await this.ff.handles()).find((h) => !before.includes(h)));
    await this.grantActiveTab();
    await this.ff.switchTo(handle);
    await waitFor("popup content", async () => (await this.ff.js<number>("return document.getElementById('app').childElementCount")) > 0);
    return handle;
  }

  /** Closes the popup window, if it is still open, and returns to the web tab. */
  async closePopup(handle: string): Promise<void> {
    if ((await this.ff.handles()).includes(handle)) {
      await this.ff.switchTo(handle);
      await this.ff.cmd("DELETE", "/window");
    }
    await this.ff.switchTo(this.web);
  }

  /** Unlocks through the popup. */
  async unlock(password: string): Promise<void> {
    const h = await this.popup();
    await waitFor("unlock form", () => this.ff.exists("#password"));
    await this.ff.type("#password", password);
    await this.ff.click("#unlock");
    await waitFor("unlocked popup", () => this.ff.exists("#search"), 30_000);
    await this.closePopup(h);
  }

  /** The keyboard shortcut: the command that Firefox's key element runs, with the web tab active. */
  async shortcut(): Promise<void> {
    await this.ff.switchTo(this.web);
    await this.ff.chrome(
      `const done = arguments[arguments.length - 1];
       const win = Services.wm.getMostRecentWindow("navigator:browser");
       win.document.querySelector(arguments[0] + " key").doCommand();
       done(true);`, KEYSET);
  }

  /** Right-clicks `css` in the web tab and picks the menu item labelled `label`. */
  async contextMenu(css: string, label: string): Promise<void> {
    await this.ff.switchTo(this.web);
    await this.ff.rightClick(css);
    await waitFor("the context menu", () => this.ff.chrome<boolean>(
      `const done = arguments[arguments.length - 1];
       done(Services.wm.getMostRecentWindow("navigator:browser").document.getElementById("contentAreaContextMenu").state === "open");`));
    const r = await this.ff.chrome<string>(
      `const done = arguments[arguments.length - 1];
       const menu = Services.wm.getMostRecentWindow("navigator:browser").document.getElementById("contentAreaContextMenu");
       const item = [...menu.querySelectorAll("menuitem")].find((m) => m.getAttribute("label") === arguments[0]);
       if (item) item.doCommand();
       menu.hidePopup();
       done(item ? "ok" : "missing, menu " + menu.state);`, label);
    if (r !== "ok") throw new Error(`context menu item ${label}: ${r}`);
  }

  /** The toolbar button's badge for the selected tab of the main window. */
  async badge(): Promise<string> {
    await this.ff.switchTo(this.web);
    return this.ff.chrome<string>(
      `const done = arguments[arguments.length - 1];
       const win = Services.wm.getMostRecentWindow("navigator:browser");
       const node = win.CustomizableUI.getWidget(arguments[0])?.forWindow(win)?.node;
       if (!node) return done("no widget");
       // The widget is a combined toolbar item; the badge is on its action button.
       const button = node.hasAttribute("badge") ? node : node.querySelector("[badge]");
       done(button ? button.getAttribute("badge") : "");`, WIDGET);
  }

  /** Adds a certificate exception for host:port with the certificate in `pem`, as the "Accept
   * the Risk and Continue" button does. */
  async addException(host: string, port: number, pem: string): Promise<void> {
    const der = Buffer.from(new X509Certificate(readFileSync(pem)).raw).toString("base64");
    await this.ff.chrome(
      `const done = arguments[arguments.length - 1];
       const [host, port, b64] = arguments;
       const cert = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB).constructX509FromBase64(b64);
       Cc["@mozilla.org/security/certoverride;1"].getService(Ci.nsICertOverrideService).rememberValidityOverride(host, port, {}, cert, false);
       done(true);`, host, port, der);
  }

  /** Grants optional host permissions, as the user's answer to a permission request does. */
  async grantOrigins(origins: string[]): Promise<void> {
    await this.ff.chrome(
      `const done = arguments[arguments.length - 1];
       const { ExtensionPermissions } = ChromeUtils.importESModule("resource://gre/modules/ExtensionPermissions.sys.mjs");
       const ext = WebExtensionPolicy.getByID(arguments[0]).extension;
       ExtensionPermissions.add(arguments[0], { permissions: [], origins: arguments[1] }, ext).then(() => done(true), (e) => done(String(e)));`,
      EXTENSION_ID, origins);
  }

  /** Puts `text` on the system clipboard, as another application would. */
  async setClipboard(text: string): Promise<void> {
    await this.ff.chrome(
      `const done = arguments[arguments.length - 1];
       Cc["@mozilla.org/widget/clipboardhelper;1"].getService(Ci.nsIClipboardHelper).copyString(arguments[0]);
       done(true);`, text);
  }

  /** The system clipboard's text, read from chrome. */
  clipboard(): Promise<string> {
    return this.ff.chrome<string>(
      `const done = arguments[arguments.length - 1];
       const t = Cc["@mozilla.org/widget/transferable;1"].createInstance(Ci.nsITransferable);
       t.init(null);
       t.addDataFlavor("text/plain");
       Services.clipboard.getData(t, Ci.nsIClipboard.kGlobalClipboard, null);
       const o = {};
       try { t.getTransferData("text/plain", o); done(o.value.QueryInterface(Ci.nsISupportsString).data); }
       catch { done(""); }`);
  }

  /** The value of `css` in the web tab's top frame, or in the iframe `frame` of it. */
  async fieldValue(css: string, frame?: string): Promise<string> {
    await this.ff.switchTo(this.web);
    if (frame !== undefined) {
      await this.ff.cmd("POST", "/frame", { id: { "element-6066-11e4-a52e-4f735466cecf": await this.ff.find(frame) } });
    }
    try {
      return await this.ff.value(css);
    } finally {
      await this.ff.cmd("POST", "/frame", { id: null });
    }
  }
}
