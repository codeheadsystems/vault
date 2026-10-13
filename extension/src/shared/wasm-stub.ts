// A development stand-in for vault-wasm, used until crates/vault-wasm is built. It implements the
// API in crates/vault-wasm/API.md over a plaintext JSON state, with no encryption, so the
// extension's flows can run end to end. `npm run build` uses it only when the module is absent and
// marks the build; `npm run sign` refuses such a build.

export type State = string;
export type Bytes = Uint8Array;
type KnownSuffix = ((host: string) => string | null) | Record<string, string | null>;

export const STUB = true;

interface StubItem {
  id: string; type: string; name: string; folder: string; favourite: boolean; notes: string;
  created: number; modified: number;
  login?: { username: string; password: string; uris: { uri: string; match: string }[] };
}
interface StubState {
  stub: 1; vault_id: string; password: string; vk: string; generation: number | null;
  unpushed: boolean; last_sync: number | null; items: StubItem[];
}

const toHex = (b: Bytes) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const parse = (state: State): StubState => JSON.parse(state) as StubState;
const fail = (code: string, message = code): never => {
  throw Object.assign(new Error(message), { code });
};

export default async function init(_options?: unknown): Promise<void> {}

export function parseSetupText(text: string): { url: string; token: string; fp: string | null; loopbackHttp: boolean } {
  let u: URL;
  try {
    u = new URL(text.trim());
  } catch {
    return fail("setup_text");
  }
  if (u.protocol !== "vault:" || !u.href.startsWith("vault://setup?")) fail("setup_text");
  const url = u.searchParams.get("url");
  const token = u.searchParams.get("token");
  if (!url || !token) return fail("setup_text");
  const server = new URL(url);
  const loopbackHttp = server.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(server.hostname);
  if (server.protocol !== "https:" && !loopbackHttp) fail("setup_text", "only https, or http to loopback");
  return { url, token: token.toUpperCase(), fp: u.searchParams.get("fp"), loopbackHttp };
}

export function decodeSecretKey(text: string): Bytes {
  const t = text.trim().toUpperCase().replace(/[-\s]/g, "");
  if (!t.startsWith("VLT1") || t.length !== 36) fail("secret_key_typo", "That secret key has a typo.");
  return new TextEncoder().encode(t.slice(4, 20));
}

export function encodeSecretKey(key: Bytes): string {
  return "VLT1-" + toHex(key).toUpperCase().match(/.{4}/g)!.join("-");
}

export function stateSummary(state: State) {
  const s = parse(state);
  return {
    vaultId: s.vault_id, generation: s.generation, unpushed: s.unpushed, stopped: null,
    pendingSecretKey: false, lastSync: s.last_sync, dropped: [] as string[],
  };
}

export function clearDropped(state: State): State {
  return state;
}

export function parseRevisions(_body: Bytes): { id: number; etag: string; size: number; created: string; token: string }[] {
  return [];
}

function suffixOf(host: string, known: KnownSuffix): string | null | undefined {
  try {
    const v = typeof known === "function" ? known(host) : known[host];
    return v === undefined ? undefined : v;
  } catch {
    return undefined;
  }
}

function registrable(host: string, known: KnownSuffix): string | undefined {
  if (/^[\d.]+$/.test(host) || host.startsWith("[")) return host;
  const s = suffixOf(host, known);
  if (s === undefined) return undefined;
  if (s === null || s === host) return host;
  const labels = host.slice(0, -s.length - 1).split(".");
  return `${labels[labels.length - 1]}.${s}`;
}

function local(host: string, known: KnownSuffix): boolean {
  if (host === "[::1]" || /^(127|10|192\.168)\./.test(host)) return true;
  return suffixOf(host, known) === null || host.endsWith("home.arpa");
}

function outcome(page: string, item: StubItem, known: KnownSuffix): "fill" | "confirm" | "none" {
  let best: "fill" | "confirm" | "none" = "none";
  const p = new URL(page);
  for (const { uri, match } of item.login?.uris ?? []) {
    let u: URL;
    try {
      u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(uri.trim()) ? uri.trim() : `https://${uri.trim()}`);
    } catch {
      continue;
    }
    let ok = false;
    if (match === "base_domain" || match === "") {
      const a = registrable(p.hostname, known);
      ok = a !== undefined && a === registrable(u.hostname, known);
    } else if (match === "host") ok = p.host === u.host;
    else if (match === "starts_with") ok = p.origin === u.origin && (p.pathname + p.search).startsWith(u.pathname + u.search);
    else if (match === "exact") ok = p.origin === u.origin && p.pathname + p.search === u.pathname + u.search;
    if (!ok) continue;
    if (u.protocol === "https:" && p.protocol === "http:") {
      if (local(p.hostname, known) && best === "none") best = "confirm";
      continue;
    }
    return "fill";
  }
  return best;
}

export function framesToFill(topUrl: string, frames: { frameId: number; url: string }[]): number[] {
  const origin = new URL(topUrl).origin;
  return frames.filter((f) => {
    try {
      return new URL(f.url).origin === origin;
    } catch {
      return false;
    }
  }).map((f) => f.frameId);
}

export function matchUri(page: string, uri: string, match: string, known: KnownSuffix): "fill" | "confirm" | "none" {
  return outcome(page, { login: { username: "", password: "", uris: [{ uri, match }] } } as StubItem, known);
}

export function pageUrl(_url: string): null {
  return null;
}

export function generatePassword(o: { length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean }) {
  let chars = "";
  if (o.upper) chars += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (o.lower) chars += "abcdefghijkmnopqrstuvwxyz";
  if (o.digits) chars += "23456789";
  if (o.symbols) chars += "!#$%&*+-=?@^_";
  const r = random(o.length);
  return { value: Array.from(r, (x) => chars[x % chars.length]).join(""), bits: o.length * Math.log2(chars.length) };
}

export function generatePassphrase(words: number, separator: string) {
  const list = ["apple", "brick", "cloud", "delta", "ember", "frost", "grove", "harbor", "ivory", "jungle"];
  return { value: Array.from(random(words), (x) => list[x % list.length]).join(separator), bits: words * Math.log2(list.length) };
}

export class Session {
  private s: StubState;
  private constructor(s: StubState) {
    this.s = s;
  }
  static unlock(state: State, _secretKey: Bytes, password: string): Session {
    const s = parse(state);
    if (s.password !== password) fail("wrong_credentials");
    return new Session(s);
  }
  static reopen(state: State, vaultKey: Bytes): Session {
    const s = parse(state);
    if (s.vk !== toHex(vaultKey)) fail("integrity.aead");
    return new Session(s);
  }
  vaultKey(): Bytes {
    return fromHex(this.s.vk);
  }
  reload(state: State): void {
    this.s = parse(state);
  }
  lock(): void {
    this.s = { ...this.s, items: [] };
  }
  free(): void {}
  readOnly(): boolean {
    return false;
  }
  list(filter?: { folder?: string; text?: string }) {
    const t = filter?.text?.toLowerCase() ?? "";
    return this.s.items
      .filter((i) => t === "" || i.name.toLowerCase().includes(t) || (i.login?.username ?? "").toLowerCase().includes(t))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((i) => ({
        id: i.id, type: i.type, name: i.name, folder: i.folder, username: i.login?.username ?? "",
        uris: (i.login?.uris ?? []).map((u) => u.uri), favourite: i.favourite, review: false, supported: true,
      }));
  }
  folders(): string[] {
    return [...new Set(this.s.items.map((i) => i.folder).filter((f) => f !== ""))].sort();
  }
  item(id: string): Record<string, unknown> {
    const i = this.s.items.find((x) => x.id === id) ?? fail("no_item");
    return structuredClone(i) as unknown as Record<string, unknown>;
  }
  private write(onDisk: State, change: (s: StubState) => void): State {
    const s = parse(onDisk);
    change(s);
    s.unpushed = true;
    this.s = s;
    return JSON.stringify(s);
  }
  add(state: State, _deviceId: Bytes, now: number, item: {
    type: string; name: string; folder?: string; favourite?: boolean; notes?: string; username?: string;
    password?: string; uris?: { uri: string; match: string }[];
  }) {
    const id = crypto.randomUUID();
    const next = this.write(state, (s) => s.items.push({
      id, type: item.type, name: item.name, folder: item.folder ?? "", favourite: item.favourite ?? false,
      notes: item.notes ?? "", created: now, modified: now,
      login: item.type === "login" ? { username: item.username ?? "", password: item.password ?? "", uris: item.uris ?? [] } : undefined,
    }));
    return { id, state: next };
  }
  update(state: State, _deviceId: Bytes, now: number, id: string, _base: object, edited: object) {
    return {
      state: this.write(state, (s) => {
        const k = s.items.findIndex((i) => i.id === id);
        if (k < 0) fail("no_item");
        s.items[k] = { ...(edited as StubItem), id, modified: now };
      }),
    };
  }
  remove(state: State, _deviceId: Bytes, _now: number, id: string) {
    return { state: this.write(state, (s) => void (s.items = s.items.filter((i) => i.id !== id))) };
  }
  suffixHosts(url: string): string[] {
    return [new URL(url).hostname];
  }
  candidates(url: string, known: KnownSuffix) {
    if (!/^https?:/.test(url)) return [];
    const out = this.s.items
      .filter((i) => i.type === "login")
      .map((i) => ({ id: i.id, name: i.name, username: i.login?.username ?? "", outcome: outcome(url, i, known) }))
      .filter((c) => c.outcome !== "none") as { id: string; name: string; username: string; outcome: "fill" | "confirm" }[];
    return out.sort((a, b) => (a.outcome !== b.outcome ? (a.outcome === "fill" ? -1 : 1) : a.name < b.name ? -1 : a.name > b.name ? 1 : a.id < b.id ? -1 : 1));
  }
  credential(id: string) {
    const i = this.s.items.find((x) => x.id === id) ?? fail("no_item");
    return { username: i.login?.username ?? "", password: i.login?.password ?? "" };
  }
  saveOffer(url: string, username: string, password: string, known: KnownSuffix) {
    const fills = this.candidates(url, known).filter((c) => c.outcome === "fill").map((c) => this.s.items.find((i) => i.id === c.id)!);
    if (fills.some((i) => i.login?.username === username && i.login?.password === password)) return { action: "none" as const };
    const same = fills.find((i) => i.login?.username === username);
    if (same) return { action: "update" as const, id: same.id };
    const u = new URL(url);
    return { action: "new" as const, name: u.hostname.replace(/\.$/, ""), uri: u.origin, match: "base_domain" as const };
  }
  restorePreview(): { added: number; changed: number; removed: number } {
    return fail("unsupported_in_stub");
  }
  restore(): { state: State } {
    return fail("unsupported_in_stub");
  }
}

type Step =
  | { type: "request"; method: "GET" | "PUT"; path: string; ifMatch?: string; ifNoneMatch?: "*"; body?: Bytes }
  | { type: "prompt"; prompt: Record<string, unknown> }
  | { type: "done"; ok: true; result: Record<string, unknown> }
  | { type: "done"; ok: false; error: { code: string; message: string } };
type Input = { type: string; status?: number; password?: string; secretKey?: Bytes; declined?: boolean };
interface CommitHost { storeCurrent(v: string, k: Bytes): void; writeState(s: State): void }

/** Each stub procedure is a list of steps; the inputs collect into `answers`. */
export class Procedure {
  private queue: ((i: Input | null) => Step | null)[] = [];
  private result: StubState | null = null;
  private written = false;
  private key: Bytes | null = null;
  private secretKey: Bytes | null = null;

  static setup(): Procedure {
    const p = new Procedure();
    p.queue = [
      () => ({ type: "prompt", prompt: { kind: "secret_key" } }),
      (i) => ((p.secretKey = i?.secretKey ?? null), { type: "prompt", prompt: { kind: "kit_vault_id" } }),
      () => ({ type: "request", method: "GET", path: "/v1/vault" }),
      (i) => (i?.type === "unreachable" ? p.end("unreachable") : { type: "prompt", prompt: { kind: "master_password", purpose: "unlock", failed: 0 } }),
      (i) => {
        if (i?.declined || !i?.password) return p.end("declined");
        p.key = random(32);
        p.result = { stub: 1, vault_id: toHex(random(16)), password: i.password, vk: toHex(p.key), generation: 1, unpushed: false, last_sync: Date.now(), items: [] };
        p.written = true;
        return { type: "done", ok: true, result: {} };
      },
    ];
    return p;
  }

  static unlock(state: State, _keys: object): Procedure {
    const p = new Procedure();
    const s = parse(state);
    let failed = 0;
    const ask = (i: Input | null): Step | null => {
      if (i?.declined) return p.end(failed > 0 ? "wrong_credentials" : "declined");
      if (i?.password !== s.password) {
        failed++;
        p.queue.unshift(ask);
        return { type: "prompt", prompt: { kind: "master_password", purpose: "unlock", failed } };
      }
      p.key = fromHex(s.vk);
      return { type: "done", ok: true, result: { sync: { outcome: "up_to_date" } } };
    };
    p.queue = [
      () => ({ type: "request", method: "GET", path: "/v1/vault" }),
      () => ({ type: "prompt", prompt: { kind: "master_password", purpose: "unlock", failed: 0 } }),
      ask,
    ];
    return p;
  }

  static sync(state: State, _keys: object, _mode: string): Procedure {
    const p = new Procedure();
    p.queue = [
      () => ({ type: "request", method: "GET", path: "/v1/vault" }),
      (i) => {
        if (i?.type !== "response") return p.end("unreachable");
        const s = parse(state);
        s.unpushed = false;
        s.last_sync = Date.now();
        p.result = s;
        p.written = true;
        return { type: "done", ok: true, result: { outcome: "up_to_date" } };
      },
    ];
    return p;
  }

  static recover(): Procedure {
    return Procedure.unsupported();
  }
  static passwd(): Procedure {
    return Procedure.unsupported();
  }
  static repairToken(): Procedure {
    return Procedure.unsupported();
  }
  static fetchRevision(): Procedure {
    return Procedure.unsupported();
  }
  private static unsupported(): Procedure {
    const p = new Procedure();
    p.queue = [() => p.end("unsupported_in_stub")];
    return p;
  }

  private end(code: string): Step {
    return { type: "done", ok: false, error: { code, message: code } };
  }

  start(_now: number): Step {
    return this.step(null, 0);
  }

  step(input: Input | null, _now: number): Step {
    const next = this.queue.shift();
    return next?.(input) ?? this.end("stub_exhausted");
  }

  applySave(): void {}

  apply(_started: State | null, onDisk: State | null, _background: boolean, _now: number, host: CommitHost) {
    if (this.written && this.result !== null) {
      // Keep the items another context wrote meanwhile.
      if (onDisk && onDisk !== "") {
        const d = parse(onDisk);
        if (d.vault_id === this.result.vault_id) this.result.items = d.items;
      }
      if (this.secretKey) host.storeCurrent(this.result.vault_id, this.secretKey);
      host.writeState(JSON.stringify(this.result));
    }
    return { written: this.written, superseded: false, mergedLocalChanges: false, expired: [], pendingLeft: false };
  }

  vaultKey(): Bytes | null {
    return this.key ? this.key.slice() : null;
  }

  free(): void {}
}
