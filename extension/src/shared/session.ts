// storage.session: memory only, cleared when the browser closes, and unreachable from content
// scripts. It holds the vault key while unlocked, the last activity time, pending save offers,
// the badge's pending pick, and the hash of the last copied value. storage.local holds settings
// without secrets, because content scripts can read it.

import type { Bytes } from "vault-wasm";
import type { Settings } from "./messages.ts";
import { hex, unhex } from "./storage.ts";

export interface Offer {
  /** The page origin, from the browser. */
  origin: string;
  /** The page URL, from the browser; used only to decide the offer, never stored in an item. */
  pageUrl: string;
  username: string;
  password: string;
  /** Milliseconds; the oldest offer goes first when there are ten. */
  at: number;
}

export const MAX_OFFERS = 10;

interface SessionData {
  vk?: string;
  lastActivity?: number;
  offers?: Offer[];
  clipHash?: string;
}

const area = () => browser.storage.session;

export async function readVaultKey(): Promise<Bytes | null> {
  const { vk } = (await area().get("vk")) as SessionData;
  return typeof vk === "string" ? unhex(vk) : null;
}

/** Stores the vault key and starts the idle clock. The caller zeroes `key` afterwards. */
export async function storeVaultKey(key: Bytes, now: number): Promise<void> {
  await area().set({ vk: hex(key), lastActivity: now } satisfies SessionData);
}

export async function readLastActivity(): Promise<number | null> {
  const { lastActivity } = (await area().get("lastActivity")) as SessionData;
  return typeof lastActivity === "number" ? lastActivity : null;
}

export async function touch(now: number): Promise<void> {
  await area().set({ lastActivity: now } satisfies SessionData);
}

/** Forgets the vault key and the pending save offers. */
export async function clearUnlocked(): Promise<void> {
  await area().remove(["vk", "lastActivity", "offers"]);
}

export async function readOffers(): Promise<Offer[]> {
  const { offers } = (await area().get("offers")) as SessionData;
  return Array.isArray(offers) ? offers : [];
}

/** The offers' read-modify-write runs under this lock, so two submits at once both count. */
const OFFERS_LOCK = "vault-offers";

/** Records an offer: one per origin, at most ten, the newest replacing the oldest. */
export function putOffer(offer: Offer): Promise<Offer[]> {
  return navigator.locks.request(OFFERS_LOCK, async () => {
    const kept = keepOffers(await readOffers(), offer);
    await area().set({ offers: kept } satisfies SessionData);
    return kept;
  });
}

/** The offers after adding `offer`: one per origin, at most ten, the oldest dropped first. */
export function keepOffers(offers: Offer[], offer: Offer): Offer[] {
  const next = offers.filter((o) => o.origin !== offer.origin);
  next.push(offer);
  next.sort((a, b) => a.at - b.at);
  return next.slice(-MAX_OFFERS);
}

export function removeOffer(origin: string): Promise<Offer[]> {
  return navigator.locks.request(OFFERS_LOCK, async () => {
    const offers = (await readOffers()).filter((o) => o.origin !== origin);
    await area().set({ offers } satisfies SessionData);
    return offers;
  });
}

export async function readClipHash(): Promise<string | null> {
  const { clipHash } = (await area().get("clipHash")) as SessionData;
  return typeof clipHash === "string" ? clipHash : null;
}

export async function storeClipHash(h: string | null): Promise<void> {
  if (h === null) await area().remove("clipHash");
  else await area().set({ clipHash: h } satisfies SessionData);
}

export const DEFAULT_SETTINGS: Settings = { idleMinutes: 15 };

export async function readSettings(): Promise<Settings> {
  const { settings } = (await browser.storage.local.get("settings")) as { settings?: Partial<Settings> };
  const idle = settings?.idleMinutes;
  return { idleMinutes: Number.isInteger(idle) && (idle as number) >= 1 ? (idle as number) : DEFAULT_SETTINGS.idleMinutes };
}

export async function writeSettings(settings: Settings): Promise<void> {
  await browser.storage.local.set({ settings });
}
