// The TypeScript-facing API of crates/vault-wasm, as crates/vault-wasm/API.md specifies it. The
// build aliases "vault-wasm" to the wasm-bindgen glue, or to src/shared/wasm-stub.ts until the
// module is built.

declare module "vault-wasm" {
  export type State = string;
  export type Bytes = Uint8Array;
  export type KnownSuffix = ((host: string) => string | null) | Record<string, string | null>;

  export default function init(options?: { module_or_path?: string | URL | Request }): Promise<unknown>;

  export function parseSetupText(text: string): { url: string; token: string; fp: string | null; loopbackHttp: boolean };
  export function decodeSecretKey(text: string): Bytes;
  export function encodeSecretKey(key: Bytes): string;
  export function stateSummary(state: State): StateSummary;
  export function clearDropped(state: State): State;
  export function parseRevisions(body: Bytes): Revision[];

  export interface StateSummary {
    vaultId: string;
    generation: number | null;
    unpushed: boolean;
    stopped: { reason: "integrity" | "token" | "credentials"; code: string; at: number } | null;
    pendingSecretKey: boolean;
    lastSync: number | null;
    dropped: string[];
  }
  export interface Revision { id: number; etag: string; size: number; created: string; token: string }

  export class Session {
    static unlock(state: State, secretKey: Bytes, password: string): Session;
    static reopen(state: State, vaultKey: Bytes): Session;
    vaultKey(): Bytes;
    reload(state: State): void;
    readOnly(): boolean;
    /** Zeroes the vault key and every string of the body; call free() afterwards. */
    lock(): void;
    free(): void;
    list(filter?: { folder?: string; text?: string }): ItemEntry[];
    folders(): string[];
    item(id: string): Record<string, unknown>;
    add(state: State, deviceId: Bytes, now: number, item: NewItem): { id: string; state: State | null };
    update(state: State, deviceId: Bytes, now: number, id: string, base: object, edited: object): { state: State | null };
    remove(state: State, deviceId: Bytes, now: number, id: string): { state: State | null };
    suffixHosts(pageUrl: string): string[];
    candidates(pageUrl: string, knownSuffix: KnownSuffix): Candidate[];
    credential(id: string): { username: string; password: string };
    saveOffer(pageUrl: string, username: string, password: string, knownSuffix: KnownSuffix): SaveOffer;
    restorePreview(revision: Procedure, itemId?: string): { added: number; changed: number; removed: number };
    restore(state: State, deviceId: Bytes, now: number, revision: Procedure, itemId?: string): { state: State; added: number; changed: number; removed: number };
  }

  export interface ItemEntry {
    id: string; type: string; name: string; folder: string; username: string;
    uris: string[]; favourite: boolean; review: boolean; supported: boolean; modified: number;
  }
  export interface NewItem {
    type: "login" | "note"; name: string; folder?: string; favourite?: boolean; notes?: string;
    username?: string; password?: string; uris?: { uri: string; match: string }[];
  }
  export interface Candidate { id: string; name: string; username: string; outcome: "fill" | "confirm" }
  export type SaveOffer =
    | { action: "none" }
    | { action: "update"; id: string }
    | { action: "new"; name: string; uri: string; match: "base_domain" };

  export function framesToFill(topUrl: string, frames: { frameId: number; url: string }[]): number[];
  export function pageUrl(url: string): Prepared | null;
  export function prepareUri(uri: string): Prepared | null;
  export function registrableDomain(url: string, knownSuffix: KnownSuffix): string | null;
  export function matchUri(pageUrl: string, uri: string, match: string, knownSuffix: KnownSuffix): "fill" | "confirm" | "none";
  export interface Prepared { scheme: string; host: string; port: number | null; pathQuery: string; origin: string }

  export function generatePassword(o: {
    length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; avoidAmbiguous: boolean;
  }): { value: string; bits: number };
  export function generatePassphrase(words: number, separator: string): { value: string; bits: number };

  export interface Keys { vaultKey?: Bytes; secretKey?: Bytes; pendingSecretKey?: Bytes }
  export type PasswdChange = "new-password" | "rekey" | "new-secret-key" | "new-secret-key-and-password";

  export class Procedure {
    static sync(state: State, keys: Keys, mode: "background" | "interactive" | "interactive-ask-again"): Procedure;
    static unlock(state: State, keys: Keys): Procedure;
    static recover(state: State, keys: Keys): Procedure;
    static passwd(state: State, keys: Keys, change: PasswdChange, kdfMemoryMib?: 64 | 128 | 256): Procedure;
    static setup(): Procedure;
    static repairToken(state: State): Procedure;
    static fetchRevision(state: State, keys: Keys, id: number): Procedure;
    start(now: number): Step;
    step(input: Input, now: number): Step;
    applySave(started: State, onDisk: State, now: number, host: CommitHost): void;
    /** `started` and `onDisk` are null after setup only. */
    apply(started: State | null, onDisk: State | null, background: boolean, now: number, host: CommitHost): Applied;
    vaultKey(): Bytes | null;
    free(): void;
  }

  export type Step =
    | { type: "request"; method: "GET" | "PUT"; path: string; ifMatch?: string; ifNoneMatch?: "*"; body?: Bytes }
    | { type: "prompt"; prompt: Prompt }
    | { type: "save"; state: State; slot: "current" | "pending"; kit: string; vaultId: string }
    | { type: "done"; ok: true; result: Record<string, unknown> }
    | { type: "done"; ok: false; error: { code: string; message: string } };

  export type Purpose = "unlock" | "credentials_changed" | "pending_secret_key" | "recovery" | "revision";
  export type Prompt =
    | { kind: "master_password"; purpose: Purpose; failed: number }
    | { kind: "master_password_and_secret_key"; purpose: Purpose }
    | { kind: "old_master_password"; failed: number }
    | { kind: "new_master_password"; rejected: string | null }
    | { kind: "secret_key" }
    | { kind: "kit_vault_id" }
    | { kind: "confirm"; confirmation: "discard_local_changes" | "no_credential_change"; description: string };

  export type Input =
    | { type: "response"; status: number; body: Bytes; date?: number }
    | { type: "unreachable" }
    | { type: "answer"; password?: string; secretKey?: Bytes; vaultId?: Bytes | null; confirmed?: boolean; declined?: boolean }
    | { type: "saved" };

  export interface CommitHost {
    storeCurrent(vaultId: string, key: Bytes): void;
    storePending(vaultId: string, key: Bytes): void;
    deletePending(vaultId: string): void;
    writeState(state: State): void;
  }
  export interface Applied {
    written: boolean; superseded: boolean; mergedLocalChanges: boolean; expired: string[]; pendingLeft: boolean;
  }
}
