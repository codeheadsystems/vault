// Fill (docs/firefox.md, Fill) and generating a password into a field.
//
// The page URL is always the tab's top frame URL from tabs.get, never anything a page or content
// script supplies. Frames are read after the choice, selected by vault-wasm, and each selected
// frame gets the fill script with the top frame's origin, which it checks against self.origin.

import { framesToFill, generatePassword, generatePassphrase, matchUri, type Candidate } from "vault-wasm";
import { fillFrame, type FillMode, type FillResult } from "../fill/fill.ts";
import type { GenerateOptions } from "../shared/messages.ts";
import { putOffer } from "../shared/session.ts";
import { knownSuffix, loadWasm } from "../shared/wasm.ts";
import { requireSession, UserError } from "./agent.ts";

export type FillOutcome =
  | { kind: "filled"; frames: number }
  | { kind: "confirm"; reason: "not_candidate" | "local_http"; host: string }
  | { kind: "refused"; reason: "http_page"; host: string }
  | { kind: "nothing"; reason: string };

/**
 * Whether the user may fill an item that is not a candidate on this page, after confirming:
 * an https page, or an http page of a local host. On any other http page the override is refused,
 * as an https item is refused there (docs/firefox.md, Fill; spec, Scheme rule). The local-host
 * test is the spec's own: an https URI for the page's host and port matches it under "host" with
 * the outcome "confirm" exactly when the host is local.
 */
function overrideAllowed(url: string): boolean {
  const u = new URL(url);
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && matchUri(url, `https://${u.host}/`, "host", knownSuffix) === "confirm";
}

/**
 * The tab the user acts on: the active tab of the focused normal window, or else of the normal
 * window used last, so that a popup-type window is never the target. Firefox's
 * windows.getLastFocused ignores its windowTypes filter, so the choice is made here.
 */
export async function activeTab(): Promise<browser.tabs.Tab> {
  const tabs = (await browser.tabs.query({ active: true, windowType: "normal" })).filter((t) => t.id !== undefined);
  if (tabs.length === 0) throw new UserError("no_tab", "There is no active tab.");
  const focused = new Set((await browser.windows.getAll({ windowTypes: ["normal"] })).filter((w) => w.focused).map((w) => w.id));
  return tabs.find((t) => focused.has(t.windowId)) ?? tabs.reduce((a, b) => ((b.lastAccessed ?? 0) > (a.lastAccessed ?? 0) ? b : a));
}

/** The URL of the tab's top frame, as the browser reports it. */
async function topUrl(tabId: number): Promise<string> {
  const tab = await browser.tabs.get(tabId);
  if (typeof tab.url !== "string") throw new UserError("no_url", "The page's address is not available.");
  return tab.url;
}

function host(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export async function candidatesFor(tabId: number): Promise<{ url: string; candidates: Candidate[] }> {
  const session = await requireSession();
  const url = await topUrl(tabId);
  return { url, candidates: session.candidates(url, knownSuffix) };
}

/** The shortcut or the context menu: fill when exactly one candidate has the outcome "fill";
 * otherwise show the number of candidates on the toolbar button, for a pick in the popup. */
export async function fillFromShortcut(tabId: number): Promise<FillOutcome> {
  let found: { url: string; candidates: Candidate[] };
  try {
    found = await candidatesFor(tabId);
  } catch (e) {
    await browser.action.setBadgeText({ tabId, text: "!" });
    await browser.action.setTitle({ tabId, title: e instanceof UserError && e.code === "locked" ? "vault is locked" : "vault cannot fill this page" });
    throw e;
  }
  const fills = found.candidates.filter((c) => c.outcome === "fill");
  if (fills.length === 1) {
    await setPickBadge(tabId, 0);
    return inject(tabId, found.url, fills[0].id, "login");
  }
  await setPickBadge(tabId, found.candidates.length);
  return { kind: "nothing", reason: found.candidates.length === 0 ? "no_candidates" : "pick" };
}

/** Shows the number of candidates on the tab's toolbar button; zero removes the tab's own value,
 * so the button shows the global one again (the number of pending save offers). */
export async function setPickBadge(tabId: number, count: number): Promise<void> {
  await browser.action.setBadgeText({ tabId, text: count === 0 ? null : String(count) });
  await browser.action.setTitle({ tabId, title: count === 0 ? null : `vault: ${count} logins for this page` });
}

/**
 * A fill the user started in the popup. An item that is not a candidate, or a candidate with the
 * outcome "confirm", fills only after the user confirmed the page's host, which the popup sends
 * back as `confirmedHost`.
 */
export async function fillFromPopup(tabId: number, id: string, confirmedHost: string | null): Promise<FillOutcome> {
  const found = await candidatesFor(tabId);
  if (!/^https?:/.test(found.url)) return { kind: "nothing", reason: "not_a_web_page" };
  const h = host(found.url);
  const candidate = found.candidates.find((c) => c.id === id);
  if (candidate === undefined && !overrideAllowed(found.url)) return { kind: "refused", reason: "http_page", host: h };
  if (confirmedHost !== h) {
    if (candidate === undefined) return { kind: "confirm", reason: "not_candidate", host: h };
    if (candidate.outcome === "confirm") return { kind: "confirm", reason: "local_http", host: h };
  }
  await setPickBadge(tabId, 0);
  return inject(tabId, found.url, id, "login");
}

/** Reads the frames, selects them, and runs the fill script in each selected frame. */
async function inject(tabId: number, url: string, id: string, mode: FillMode): Promise<FillOutcome> {
  const session = await requireSession();
  await loadWasm();
  const frames = await browser.webNavigation.getAllFrames({ tabId });
  if (!frames) return { kind: "nothing", reason: "no_frames" };
  const top = frames.find((f) => f.frameId === 0);
  if (top?.url !== url) return { kind: "nothing", reason: "navigated" };
  const selected = framesToFill(url, frames.map((f) => ({ frameId: f.frameId, url: f.url })));
  if (selected.length === 0) return { kind: "nothing", reason: "no_frames" };
  const { username, password } = session.credential(id);
  const results = await browser.scripting.executeScript({
    target: { tabId, frameIds: selected },
    func: fillFrame,
    args: [new URL(url).origin, username, password, mode],
  });
  const filled = results.filter((r) => {
    const v = r.result as FillResult | undefined;
    return v !== undefined && v.origin && (v.passwordsFilled > 0 || v.usernameFilled);
  }).length;
  return filled > 0 ? { kind: "filled", frames: filled } : { kind: "nothing", reason: "no_fields" };
}

export async function generate(options: GenerateOptions): Promise<{ value: string; bits: number }> {
  await loadWasm();
  return options.kind === "password"
    ? generatePassword(options)
    : generatePassphrase(options.words, options.separator);
}

/**
 * Generates a password into a visible password field of a selected frame (FF-5), and records it
 * as a pending save offer for the page's origin, so a form that fails to submit does not lose it.
 * `frameId`, from the context menu, limits the fill to the frame the user clicked in.
 */
export async function generateIntoField(tabId: number, options: GenerateOptions, frameId: number | null): Promise<FillOutcome> {
  await requireSession();
  const url = await topUrl(tabId);
  if (!/^https?:/.test(url)) return { kind: "nothing", reason: "not_a_web_page" };
  const frames = (await browser.webNavigation.getAllFrames({ tabId })) ?? [];
  if (frames.find((f) => f.frameId === 0)?.url !== url) return { kind: "nothing", reason: "navigated" };
  let selected = framesToFill(url, frames.map((f) => ({ frameId: f.frameId, url: f.url })));
  if (frameId !== null) selected = selected.filter((f) => f === frameId);
  else selected.sort((a, b) => (a === 0 ? -1 : b === 0 ? 1 : 0));
  const { value } = await generate(options);
  const origin = new URL(url).origin;
  // One frame at a time, top frame first, until one has a password field.
  for (const f of selected) {
    const [r] = await browser.scripting.executeScript({
      target: { tabId, frameIds: [f] },
      func: fillFrame,
      args: [origin, "", value, "generate"],
    });
    const v = r?.result as FillResult | undefined;
    if (v?.origin && v.passwordsFilled > 0) {
      await putOffer({ origin, pageUrl: url, username: "", password: value, at: Date.now() });
      return { kind: "filled", frames: 1 };
    }
  }
  return { kind: "nothing", reason: "no_password_field" };
}
