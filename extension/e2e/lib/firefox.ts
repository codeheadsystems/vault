// A small WebDriver client for headless Firefox through geckodriver, for the end-to-end tests.
//
// GECKODRIVER and FIREFOX name the binaries when they are not on PATH. geckodriver runs with
// --allow-system-access, so the tests can run chrome-context scripts: adding certificate
// exceptions, granting activeTab as a click on the toolbar button does, firing the keyboard
// shortcut's command, and reading the clipboard.

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { resolve } from "node:path";

export const EXTENSION_ID: string = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "..", "..", "static", "manifest.json"), "utf8"),
).browser_specific_settings.gecko.id;
export const UUID = "5a5f2a6e-0000-4000-8000-00000000e2e0";
export const BASE = `moz-extension://${UUID}/`;
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf";

export async function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => ok(port));
    });
    s.on("error", fail);
  });
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const dist = resolve(import.meta.dirname, "..", "..", "dist");
/** dist/ was built with the vault-wasm stub. */
export const STUB = existsSync(resolve(dist, "STUB"));
/** dist/ was built with the end-to-end timings (src/shared/timing.ts). */
export const E2E_TIMING = existsSync(resolve(dist, "E2E_TIMING"));
// The suite tests the real module: a stub build fails it unless E2E_ALLOW_STUB=1 says otherwise.
if (STUB && process.env.E2E_ALLOW_STUB !== "1") {
  throw new Error("dist/ is a stub build; build vault-wasm (npm run e2e does), or set E2E_ALLOW_STUB=1");
}

export async function waitFor<T>(what: string, fn: () => Promise<T | null | undefined | false>, timeoutMs = 15_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown = null;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v !== null && v !== undefined && v !== false) return v;
    } catch (e) {
      last = e;
    }
    await sleep(200);
  }
  throw new Error(`timed out waiting for ${what}${last ? `: ${String(last)}` : ""}`);
}

export class WebDriverError extends Error {}

export class Firefox {
  private gd: ChildProcess;
  private port: number;
  sid = "";

  private constructor(gd: ChildProcess, port: number) {
    this.gd = gd;
    this.port = port;
  }

  /** The profile directory geckodriver gave this session. */
  profile = "";

  static async start(prefs: Record<string, unknown> = {}, options: { headless?: boolean; profile?: string } = {}): Promise<Firefox> {
    const port = await freePort();
    const gd = spawn(process.env.GECKODRIVER ?? "geckodriver", ["--allow-system-access", "--port", String(port)], {
      stdio: ["ignore", "ignore", process.env.E2E_VERBOSE ? "inherit" : "ignore"],
    });
    const ff = new Firefox(gd, port);
    await waitFor("geckodriver", async () => (await fetch(`http://127.0.0.1:${port}/status`)).ok, 10_000);
    const caps = {
      capabilities: {
        alwaysMatch: {
          browserName: "firefox",
          acceptInsecureCerts: false,
          "moz:firefoxOptions": {
            ...(process.env.FIREFOX ? { binary: process.env.FIREFOX } : {}),
            args: [...(options.headless === false ? [] : ["-headless"]), ...(options.profile ? ["-profile", options.profile] : [])],
            prefs: {
              "extensions.webextensions.uuids": JSON.stringify({ [EXTENSION_ID]: UUID }),
              // Optional permissions are granted without the doorhanger a person would accept.
              "extensions.webextOptionalPermissionPrompts": false,
              // A temporary add-on is uninstalled when Firefox quits; keep its storage and UUID, so
              // that a restart on the same profile finds the state, as a signed install would.
              "extensions.webextensions.keepStorageOnUninstall": true,
              "extensions.webextensions.keepUuidOnUninstall": true,
              ...prefs,
            },
          },
        },
      },
    };
    const v = (await ff.raw("POST", "/session", caps)) as { sessionId: string; capabilities: { browserVersion: string; "moz:profile": string } };
    ff.sid = v.sessionId;
    ff.profile = v.capabilities["moz:profile"];
    return ff;
  }

  async quit(): Promise<void> {
    try {
      if (this.sid) await this.raw("DELETE", `/session/${this.sid}`);
    } finally {
      this.gd.kill();
    }
  }

  private async raw(method: string, path: string, body?: unknown): Promise<unknown> {
    const r = await fetch(`http://127.0.0.1:${this.port}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = (await r.json()) as { value: unknown };
    if (!r.ok) {
      const e = json.value as { error?: string; message?: string };
      throw new WebDriverError(`${method} ${path}: ${e.error}: ${e.message}`);
    }
    return json.value;
  }

  cmd(method: string, path: string, body?: unknown): Promise<unknown> {
    return this.raw(method, `/session/${this.sid}${path}`, body);
  }

  /** Installs dist/ as a temporary add-on. */
  installExtension(dir = resolve(import.meta.dirname, "..", "..", "dist")): Promise<unknown> {
    return this.cmd("POST", "/moz/addon/install", { path: dir, temporary: true });
  }

  nav(url: string): Promise<unknown> {
    return this.cmd("POST", "/url", { url });
  }

  js<T = unknown>(script: string, ...args: unknown[]): Promise<T> {
    return this.cmd("POST", "/execute/sync", { script, args }) as Promise<T>;
  }

  jsAsync<T = unknown>(script: string, ...args: unknown[]): Promise<T> {
    return this.cmd("POST", "/execute/async", { script, args }) as Promise<T>;
  }

  /** Runs a script in the browser's chrome context. */
  async chrome<T = unknown>(script: string, ...args: unknown[]): Promise<T> {
    await this.cmd("POST", "/moz/context", { context: "chrome" });
    try {
      return (await this.cmd("POST", "/execute/async", { script, args })) as T;
    } finally {
      await this.cmd("POST", "/moz/context", { context: "content" });
    }
  }

  handle(): Promise<string> {
    return this.cmd("GET", "/window") as Promise<string>;
  }

  async handles(): Promise<string[]> {
    return (await this.cmd("GET", "/window/handles")) as string[];
  }

  switchTo(handle: string): Promise<unknown> {
    return this.cmd("POST", "/window", { handle });
  }

  async newTab(url: string): Promise<string> {
    const { handle } = (await this.cmd("POST", "/window/new", { type: "tab" })) as { handle: string };
    await this.switchTo(handle);
    await this.nav(url);
    return handle;
  }

  async find(css: string): Promise<string> {
    const v = (await this.cmd("POST", "/element", { using: "css selector", value: css })) as Record<string, string>;
    return v[ELEMENT];
  }

  async exists(css: string): Promise<boolean> {
    const v = (await this.cmd("POST", "/elements", { using: "css selector", value: css })) as unknown[];
    return v.length > 0;
  }

  async click(css: string): Promise<void> {
    await this.cmd("POST", `/element/${await this.find(css)}/click`, {});
  }

  async type(css: string, text: string): Promise<void> {
    const id = await this.find(css);
    await this.cmd("POST", `/element/${id}/clear`, {});
    await this.cmd("POST", `/element/${id}/value`, { text });
  }

  async text(css: string): Promise<string> {
    return (await this.cmd("GET", `/element/${await this.find(css)}/text`)) as string;
  }

  async value(css: string): Promise<string> {
    return this.js<string>("return document.querySelector(arguments[0]).value", css);
  }

  /** Waits for an element and clicks it, finding it again when the page re-rendered it. */
  async clickWhenReady(css: string, timeoutMs = 15_000): Promise<void> {
    await waitFor(css, async () => {
      if (!(await this.exists(css))) return false;
      try {
        await this.click(css);
        return true;
      } catch (e) {
        if (String(e).includes("stale element")) return false;
        throw e;
      }
    }, timeoutMs);
  }

  async rightClick(css: string): Promise<void> {
    const id = await this.find(css);
    await this.cmd("POST", "/actions", {
      actions: [{
        type: "pointer", id: "mouse", parameters: { pointerType: "mouse" },
        actions: [{ type: "pointerMove", origin: { [ELEMENT]: id }, x: 0, y: 0 }, { type: "pointerDown", button: 2 }, { type: "pointerUp", button: 2 }],
      }],
    });
  }
}
