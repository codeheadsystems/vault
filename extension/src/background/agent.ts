// The background script's vault session (docs/firefox.md, Background script): the unlocked body
// in WASM memory, reopened from the vault key in storage.session by each new instance, and the
// idle lock.

import { Procedure, Session, stateSummary, type State } from "vault-wasm";
import { DECLINE, drive } from "../shared/drive.ts";
import {
  clearUnlocked, readLastActivity, readSettings, readVaultKey, storeVaultKey, touch,
} from "../shared/session.ts";
import { idleExpired, SessionSlot } from "../shared/lifecycle.ts";
import { Store, webLock, type Config } from "../shared/storage.ts";
import { IDLE_CHECK_MINUTES, SYNC_MINUTES } from "../shared/timing.ts";
import { loadWasm } from "../shared/wasm.ts";

export const store = new Store(indexedDB, webLock);

export const ALARM_IDLE = "idle";
export const ALARM_SYNC = "sync";
export const ALARM_CLIPBOARD = "clipboard";

const slot = new SessionSlot<Session>();

export class UserError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Locks when the idle time has passed since the last user action. Runs before every request,
 * at the start of every instance, and from the minute alarm. */
export async function lockIfIdle(now = Date.now()): Promise<void> {
  const key = await readVaultKey();
  if (key === null) {
    if (slot.peek() !== null) await lock();
    return;
  }
  key.fill(0);
  const [last, settings] = await Promise.all([readLastActivity(), readSettings()]);
  if (idleExpired(now, last, settings.idleMinutes)) await lock();
}

/** Records a user action for the idle lock, when unlocked. */
export async function recordActivity(now = Date.now()): Promise<void> {
  if ((await readLastActivity()) !== null) await touch(now);
}

/**
 * Forgets the vault key first, so that no new instance or open in flight can reopen the vault,
 * then the pending save offers, the idle and sync alarms, and the session. The clipboard alarm
 * stays, so a password copied before the lock is still cleared.
 */
export async function lock(): Promise<void> {
  await clearUnlocked();
  slot.drop();
  await Promise.all([browser.alarms.clear(ALARM_IDLE), browser.alarms.clear(ALARM_SYNC)]);
  await browser.action.setBadgeText({ text: "" });
}

/** The unlocked session, reopened from the vault key in storage.session when this instance has
 * none yet; null when locked. Concurrent callers share one open. */
export function getSession(): Promise<Session | null> {
  return slot.get(openFromSessionKey);
}

async function openFromSessionKey(): Promise<Session | null> {
  const key = await readVaultKey();
  if (key === null) return null;
  try {
    const state = await store.readState();
    if (state === null) return null;
    await loadWasm();
    return Session.reopen(state, key);
  } catch {
    // The key no longer opens the local file, for example after a credential change elsewhere
    // that this context has not taken over.
    await clearUnlocked();
    return null;
  } finally {
    key.fill(0);
  }
}

export async function requireSession(): Promise<Session> {
  const s = await getSession();
  if (s === null) throw new UserError("locked", "The vault is locked.");
  return s;
}

/** Reloads the session after a commit by this or another context. A context that changed the
 * vault key (a credential change in the vault page) stores the new key first; the session is
 * then reopened with it. */
export async function reload(): Promise<void> {
  // Reload in place, so that a request holding this session meanwhile never sees it freed; a
  // reload that fails (the vault key changed) reopens with the key now in storage.session.
  const state = await store.readState();
  const current = slot.peek();
  if (current !== null && state !== null) {
    try {
      current.reload(state);
      return;
    } catch {
      // Fall through and reopen.
    }
  }
  slot.drop();
  await getSession();
}

export async function requireConfigured(): Promise<{ state: State; config: Config }> {
  const [state, config] = await Promise.all([store.readState(), store.readConfig()]);
  if (state === null || config === null) throw new UserError("not_configured", "Set up the vault first.");
  return { state, config };
}

/** Starts the alarms that run while unlocked. */
export async function startAlarms(): Promise<void> {
  await browser.alarms.create(ALARM_IDLE, { periodInMinutes: IDLE_CHECK_MINUTES });
  await browser.alarms.create(ALARM_SYNC, { periodInMinutes: SYNC_MINUTES });
}

/**
 * Unlocks with the master password: the vault-client unlock procedure, which pulls first. Any
 * prompt other than the first master password (a credential change on another device, for
 * example) is declined, and the vault page resolves it.
 */
export async function unlock(password: string): Promise<{ sync: unknown }> {
  const { state, config } = await requireConfigured();
  await loadWasm();
  const vaultId = stateSummary(state).vaultId;
  const keys = await store.readSecretKeys(vaultId);
  const proc = Procedure.unlock(state, {
    secretKey: keys.current ?? undefined,
    pendingSecretKey: keys.pending ?? undefined,
  });
  keys.current?.fill(0);
  keys.pending?.fill(0);
  try {
    return await finishUnlock(proc, state, config, password);
  } finally {
    proc.free();
  }
}

async function finishUnlock(proc: Procedure, state: State, config: Config, password: string): Promise<{ sync: unknown }> {
  let wrong = false;
  let needsPage: string | null = null;
  const done = await drive(proc, config, {
    prompt: async (p) => {
      if (p.kind === "master_password" && p.purpose === "unlock") {
        if (p.failed === 0) return { type: "answer", password };
        wrong = true;
      } else {
        needsPage = p.kind;
      }
      return DECLINE;
    },
  });
  await store.commit((onDisk, host) => proc.apply(state, onDisk ?? state, false, Date.now(), host));
  if (wrong) throw new UserError("wrong_password", "Wrong master password.");
  if (!done.ok) {
    if (needsPage !== null) {
      throw new UserError("needs_vault_page", "The vault needs the vault page to unlock (another device changed the credentials).");
    }
    throw new UserError(done.error.code, done.error.message);
  }
  const key = proc.vaultKey();
  if (key === null) throw new UserError("no_key", "The unlock gave no vault key.");
  try {
    await storeVaultKey(key, Date.now());
  } finally {
    key.fill(0);
  }
  slot.drop();
  await getSession();
  await startAlarms();
  return { sync: done.result.sync };
}

/** A local edit under the state lock; the session already holds the result. */
export async function edit<T extends { state: State | null }>(
  fn: (s: Session, onDisk: State, deviceId: Uint8Array, now: number) => T,
): Promise<T> {
  const s = await requireSession();
  const { config } = await requireConfigured();
  return store.commit((onDisk, host) => {
    if (onDisk === null) throw new UserError("not_configured", "Set up the vault first.");
    const r = fn(s, onDisk, config.deviceId, Date.now());
    if (r.state !== null) host.writeState(r.state);
    return r;
  });
}
