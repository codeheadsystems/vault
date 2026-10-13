// Messages between the extension's contexts, and their validation (docs/firefox.md, Messages).
//
// The popup and the vault page send a Request to the background script. A content script (the
// save watcher) sends only a SaveSubmit. The background script checks the sender first and then
// the shape, and drops anything that fails either check.

import type { NewItem } from "vault-wasm";

export type GenerateOptions =
  | { kind: "password"; length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; avoidAmbiguous: boolean }
  | { kind: "passphrase"; words: number; separator: string };

export interface Settings {
  /** Minutes without a user action before the vault locks. */
  idleMinutes: number;
}

export type Request =
  | { type: "status" }
  | { type: "unlock"; password: string }
  | { type: "lock" }
  | { type: "list"; text: string }
  | { type: "item"; id: string }
  | { type: "copy"; id: string; field: "username" | "password" }
  | { type: "candidates" }
  | { type: "fill"; id: string; confirmedHost: string | null }
  | { type: "add"; item: NewItem }
  | { type: "update"; id: string; base: Record<string, unknown>; edited: Record<string, unknown> }
  | { type: "remove"; id: string }
  | { type: "generate"; options: GenerateOptions }
  | { type: "generateIntoField"; options: GenerateOptions }
  | { type: "offerSave"; origin: string }
  | { type: "offerDismiss"; origin: string }
  | { type: "syncNow" }
  | { type: "stateChanged" }
  | { type: "setSettings"; settings: Settings };

/** The save watcher's one message. */
export interface SaveSubmit {
  type: "saveSubmit";
  username: string;
  password: string;
}

/** Requests that are user actions and so count as activity for the idle lock. `status`, which
 * the popup sends whenever it opens, `syncNow`, and `stateChanged` do not count. */
export const USER_ACTIONS: ReadonlySet<Request["type"]> = new Set<Request["type"]>([
  "unlock", "list", "item", "copy", "candidates", "fill", "add", "update", "remove", "generate",
  "generateIntoField", "offerSave", "offerDismiss", "setSettings",
]);

const MAX_TEXT = 4096;
const MAX_NOTES = 65536;
const MAX_JSON = 1 << 20;

type Check = (v: unknown) => boolean;

const str = (max = MAX_TEXT): Check => (v) => typeof v === "string" && v.length <= max;
const bool: Check = (v) => typeof v === "boolean";
const int = (min: number, max: number): Check => (v) => Number.isInteger(v) && (v as number) >= min && (v as number) <= max;
const oneOf = (...xs: string[]): Check => (v) => typeof v === "string" && xs.includes(v);
const nullable = (c: Check): Check => (v) => v === null || c(v);
const optional = (c: Check): Check => (v) => v === undefined || c(v);
const id: Check = (v) => typeof v === "string" && /^[0-9a-f-]{1,64}$/.test(v);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && Object.getPrototypeOf(v) === Object.prototype;
}

/** An object with exactly the given keys (optional ones may be absent), each passing its check. */
function exact(shape: Record<string, Check>): Check {
  return (v) => {
    if (!isPlainObject(v)) return false;
    for (const k of Object.keys(v)) if (!Object.hasOwn(shape, k)) return false;
    for (const [k, c] of Object.entries(shape)) if (!c(v[k])) return false;
    return true;
  };
}

const arrayOf = (c: Check, max: number): Check => (v) => Array.isArray(v) && v.length <= max && v.every(c);

/** A JSON object of bounded size, such as an item as Session.item returns it. */
const jsonObject: Check = (v) => {
  if (!isPlainObject(v)) return false;
  try {
    return JSON.stringify(v).length <= MAX_JSON;
  } catch {
    return false;
  }
};

const newItem = exact({
  type: oneOf("login", "note"),
  name: (v) => str()(v) && (v as string).trim().length > 0,
  folder: optional(str()),
  favourite: optional(bool),
  notes: optional(str(MAX_NOTES)),
  username: optional(str()),
  password: optional(str()),
  uris: optional(arrayOf(exact({ uri: str(), match: oneOf("base_domain", "host", "starts_with", "exact", "never") }), 100)),
});

const generateOptions: Check = (v) =>
  exact({
    kind: oneOf("password"), length: int(4, 128), upper: bool, lower: bool, digits: bool, symbols: bool, avoidAmbiguous: bool,
  })(v) || exact({ kind: oneOf("passphrase"), words: int(3, 20), separator: str(8) })(v);

const origin: Check = (v) => {
  if (typeof v !== "string" || v.length > MAX_TEXT) return false;
  try {
    return new URL(v).origin === v;
  } catch {
    return false;
  }
};

const REQUESTS: Record<Request["type"], Check> = {
  status: exact({ type: oneOf("status") }),
  unlock: exact({ type: oneOf("unlock"), password: str() }),
  lock: exact({ type: oneOf("lock") }),
  list: exact({ type: oneOf("list"), text: str(256) }),
  item: exact({ type: oneOf("item"), id }),
  copy: exact({ type: oneOf("copy"), id, field: oneOf("username", "password") }),
  candidates: exact({ type: oneOf("candidates") }),
  fill: exact({ type: oneOf("fill"), id, confirmedHost: nullable(str(256)) }),
  add: exact({ type: oneOf("add"), item: newItem }),
  update: exact({ type: oneOf("update"), id, base: jsonObject, edited: jsonObject }),
  remove: exact({ type: oneOf("remove"), id }),
  generate: exact({ type: oneOf("generate"), options: generateOptions }),
  generateIntoField: exact({ type: oneOf("generateIntoField"), options: generateOptions }),
  offerSave: exact({ type: oneOf("offerSave"), origin }),
  offerDismiss: exact({ type: oneOf("offerDismiss"), origin }),
  syncNow: exact({ type: oneOf("syncNow") }),
  stateChanged: exact({ type: oneOf("stateChanged") }),
  setSettings: exact({ type: oneOf("setSettings"), settings: exact({ idleMinutes: int(1, 1440) }) }),
};

/** The request, when `msg` has exactly a known request's shape; otherwise null. */
export function parseRequest(msg: unknown): Request | null {
  if (!isPlainObject(msg) || typeof msg.type !== "string" || !Object.hasOwn(REQUESTS, msg.type)) return null;
  return REQUESTS[msg.type as Request["type"]](msg) ? (msg as Request) : null;
}

/** The save watcher's message, when `msg` has exactly its shape; otherwise null. */
export function parseSaveSubmit(msg: unknown): SaveSubmit | null {
  const ok = exact({ type: oneOf("saveSubmit"), username: str(), password: (v) => str()(v) && (v as string).length > 0 })(msg);
  return ok ? (msg as SaveSubmit) : null;
}

/** The parts of runtime.MessageSender the checks read. */
export interface Sender {
  id?: string;
  url?: string;
  tab?: { id?: number; url?: string };
  frameId?: number;
  envType?: string;
}

/** Whether `url` is under the extension's base URL. A prefix test, because WHATWG URL parsing
 * gives a moz-extension URL an opaque origin outside Firefox. */
function underBase(url: string | undefined, base: string): boolean {
  return typeof url === "string" && base.endsWith("/") && url.startsWith(base);
}

/** A sender is an extension page (the popup or the vault page): this extension, a URL under the
 * extension's base URL, and either no tab (the popup) or a tab that itself shows an extension
 * page (the vault page, which runs in a tab). `extensionBase` is runtime.getURL(""), such as
 * "moz-extension://<uuid>/". Firefox also reports a content script's envType as "content_child". */
export function isExtensionPage(sender: Sender, runtimeId: string, extensionBase: string): boolean {
  if (sender.id !== runtimeId || !underBase(sender.url, extensionBase)) return false;
  if (sender.envType !== undefined && sender.envType !== "addon_child") return false;
  return sender.tab === undefined || underBase(sender.tab.url, extensionBase);
}

/** A sender is this extension's content script in the top frame of a tab. The page URL then comes
 * from `sender.url`, which the browser reports, never from the message. */
export function isTopFrameContentScript(sender: Sender, runtimeId: string): boolean {
  if (sender.id !== runtimeId || sender.tab === undefined || sender.frameId !== 0) return false;
  if (sender.envType !== undefined && sender.envType !== "content_child") return false;
  return typeof sender.url === "string" && /^https?:/.test(sender.url);
}

export type Response<T = unknown> = { ok: true; value: T } | { ok: false; code: string; message: string };
