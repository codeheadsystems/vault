// Persistent storage (docs/firefox.md, Storage).
//
// IndexedDB in the extension's own origin holds the local state, the server configuration, and
// the secret keys; content scripts cannot open it. Every change to the local state runs under the
// Web Locks lock "vault-state", which every context shares, and in one IndexedDB transaction that
// first reads the state on disk.

import type { Bytes, CommitHost, State } from "vault-wasm";

export const DB_NAME = "vault";
const DB_VERSION = 1;
const KV = "kv";
export const STATE_LOCK = "vault-state";

/** The server settings from the setup text, and this device's ID. */
export interface Config {
  /** The server URL as the setup text gives it. */
  url: string;
  token: string;
  fp: string | null;
  /** The host permission the extension requested for the server, `<scheme>://<host>/*`. */
  permission: string;
  deviceId: Bytes;
}

export interface SecretKeys {
  current: Bytes | null;
  pending: Bytes | null;
}

/** What a commit callback may write besides the vault-client commit host's writes. */
export interface StoreHost extends CommitHost {
  writeConfig(config: Config): void;
}

/** navigator.locks.request, or a stand-in in tests. */
export type LockFn = <T>(name: string, fn: () => Promise<T>) => Promise<T>;

export const webLock: LockFn = (name, fn) => navigator.locks.request(name, { mode: "exclusive" }, fn);

const keyName = (vaultId: string, slot: "current" | "pending") => `secret:${vaultId}:${slot}`;

function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export class Store {
  private db: Promise<IDBDatabase> | null = null;
  private readonly idb: IDBFactory;
  private readonly lock: LockFn;

  constructor(idb: IDBFactory, lock: LockFn) {
    this.idb = idb;
    this.lock = lock;
  }

  private open(): Promise<IDBDatabase> {
    this.db ??= new Promise((resolve, reject) => {
      const req = this.idb.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => req.result.createObjectStore(KV);
      req.onsuccess = () => {
        const db = req.result;
        // Another context upgrading the database later must not be blocked by this connection.
        db.onversionchange = () => {
          db.close();
          this.db = null;
        };
        resolve(db);
      };
      req.onerror = () => reject(req.error);
    });
    return this.db;
  }

  private async get<T>(key: string): Promise<T | null> {
    const db = await this.open();
    const v = await done(db.transaction(KV, "readonly").objectStore(KV).get(key));
    return (v ?? null) as T | null;
  }

  readState(): Promise<State | null> {
    return this.get<State>("state");
  }

  readConfig(): Promise<Config | null> {
    return this.get<Config>("config");
  }

  async readSecretKeys(vaultId: string): Promise<SecretKeys> {
    const db = await this.open();
    const kv = db.transaction(KV, "readonly").objectStore(KV);
    const [current, pending] = await Promise.all([
      done(kv.get(keyName(vaultId, "current"))),
      done(kv.get(keyName(vaultId, "pending"))),
    ]);
    return { current: (current as Bytes | undefined) ?? null, pending: (pending as Bytes | undefined) ?? null };
  }

  /**
   * Runs `fn` under the "vault-state" lock with the state on disk, in one read-write transaction.
   * `fn` is synchronous and only queues writes through the host, as vault-client's commit rule
   * does; the promise resolves with its result once the transaction has committed, and rejects
   * with nothing written when `fn` throws.
   */
  commit<T>(fn: (onDisk: State | null, host: StoreHost) => T): Promise<T> {
    return this.lock(STATE_LOCK, async () => {
      const db = await this.open();
      return new Promise<T>((resolve, reject) => {
        const tx = db.transaction(KV, "readwrite");
        const kv = tx.objectStore(KV);
        let result: T;
        let failed = false;
        const host: StoreHost = {
          storeCurrent: (vaultId, key) => void kv.put(key.slice(), keyName(vaultId, "current")),
          storePending: (vaultId, key) => void kv.put(key.slice(), keyName(vaultId, "pending")),
          deletePending: (vaultId) => void kv.delete(keyName(vaultId, "pending")),
          writeState: (state) => void kv.put(state, "state"),
          writeConfig: (config) => void kv.put(config, "config"),
        };
        const read = kv.get("state");
        read.onsuccess = () => {
          try {
            result = fn((read.result as State | undefined) ?? null, host);
          } catch (e) {
            failed = true;
            tx.abort();
            reject(e);
          }
        };
        tx.oncomplete = () => resolve(result);
        tx.onabort = () => {
          if (!failed) reject(tx.error ?? new Error("transaction aborted"));
        };
      });
    });
  }

  /** Removes everything: the state, the configuration, and every secret key. */
  async clear(): Promise<void> {
    await this.lock(STATE_LOCK, async () => {
      const db = await this.open();
      const tx = db.transaction(KV, "readwrite");
      tx.objectStore(KV).clear();
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error);
      });
    });
  }
}

export function hex(b: Bytes): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function unhex(s: string): Bytes {
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) throw new Error("not lowercase hex");
  return Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
}

export async function sha256Hex(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
