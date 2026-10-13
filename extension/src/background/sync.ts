// Background sync (docs/firefox.md, Background script): on unlock, after every local change, and
// every 5 minutes while unlocked. One runs at a time; a request during a run sets a flag that runs
// one more afterwards.

import { Procedure } from "vault-wasm";
import { DECLINE, drive } from "../shared/drive.ts";
import { coalesce } from "../shared/lifecycle.ts";
import { readVaultKey } from "../shared/session.ts";
import { loadWasm } from "../shared/wasm.ts";
import { reload, store } from "./agent.ts";

/** Why the last sync could not run or failed, for the popup; null after a successful one. */
export interface SyncIssue {
  code: string;
  message: string;
  at: number;
}

/** The last sync's issue, kept in storage.session so that it outlives this instance. */
export async function syncIssue(): Promise<SyncIssue | null> {
  const { syncIssue } = (await browser.storage.session.get("syncIssue")) as { syncIssue?: SyncIssue };
  return syncIssue ?? null;
}

async function setIssue(issue: SyncIssue | null): Promise<void> {
  if (issue === null) await browser.storage.session.remove("syncIssue");
  else await browser.storage.session.set({ syncIssue: issue });
}

/** Requests a sync; resolves when the run that covers this request has finished. */
export const requestSync = coalesce(() => syncOnce());

async function syncOnce(): Promise<void> {
  const [state, config] = await Promise.all([store.readState(), store.readConfig()]);
  if (state === null || config === null) return;
  if (!(await browser.permissions.contains({ origins: [config.permission] }))) {
    await setIssue({
      code: "host_permission",
      message: `vault has no permission to reach ${config.permission}. Grant it in the vault page.`,
      at: Date.now(),
    });
    return;
  }
  const key = await readVaultKey();
  if (key === null) return;
  await loadWasm();
  let proc: Procedure;
  try {
    proc = Procedure.sync(state, { vaultKey: key }, "background");
  } finally {
    key.fill(0);
  }
  let applied;
  let done;
  try {
    done = await drive(proc, config, { prompt: async () => DECLINE });
    applied = await store.commit((onDisk, host) => proc.apply(state, onDisk ?? state, true, Date.now(), host));
  } finally {
    proc.free();
  }
  await setIssue(done.ok ? null : { code: done.error.code, message: done.error.message, at: Date.now() });
  if (applied.written) await reload();
}
