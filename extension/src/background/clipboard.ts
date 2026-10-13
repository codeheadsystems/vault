// Copying a username or password (docs/firefox.md, Clipboard). The value's SHA-256 goes to
// storage.session, and an alarm 45 seconds later clears the clipboard when it still holds the
// same value. Both work from the background script with no extension page open.

import { readClipHash, storeClipHash } from "../shared/session.ts";
import { sha256Hex } from "../shared/storage.ts";
import { CLIPBOARD_CLEAR_MINUTES } from "../shared/timing.ts";
import { ALARM_CLIPBOARD, requireSession } from "./agent.ts";

export async function copy(id: string, field: "username" | "password"): Promise<void> {
  const session = await requireSession();
  const value = session.credential(id)[field];
  await navigator.clipboard.writeText(value);
  await storeClipHash(await sha256Hex(value));
  await browser.alarms.create(ALARM_CLIPBOARD, { delayInMinutes: CLIPBOARD_CLEAR_MINUTES });
}

/** Clears the clipboard when it still holds the copied value. */
export async function clearClipboard(): Promise<void> {
  const expected = await readClipHash();
  if (expected === null) return;
  try {
    const current = await navigator.clipboard.readText();
    if ((await sha256Hex(current)) === expected) await navigator.clipboard.writeText("");
  } finally {
    await storeClipHash(null);
  }
}
