// Save offers (docs/firefox.md, Save offers). The save watcher reports a submitted login form in
// a tab's top frame; the page URL comes from the sender as the browser reports it. Nothing is
// saved without the user's confirmation in the popup.

import { putOffer, readOffers, removeOffer } from "../shared/session.ts";
import { knownSuffix } from "../shared/wasm.ts";
import { edit, getSession, requireSession, UserError } from "./agent.ts";

/** Records an offer for a submitted form. Ignored while locked, and when vault-client decides
 * there is nothing to offer. */
export async function onSubmit(pageUrl: string, username: string, password: string): Promise<void> {
  const session = await getSession();
  if (session === null) return;
  let origin: string;
  try {
    origin = new URL(pageUrl).origin;
  } catch {
    return;
  }
  if (session.saveOffer(pageUrl, username, password, knownSuffix).action === "none") return;
  await putOffer({ origin, pageUrl, username, password, at: Date.now() });
  await updateOfferBadge();
}

export interface OfferView {
  origin: string;
  username: string;
  action: "update" | "new";
  /** The item an update changes, or the name of the new item. */
  name: string;
}

/** The pending offers as the popup shows them, each decided again against the current vault. */
export async function listOffers(): Promise<OfferView[]> {
  const session = await getSession();
  if (session === null) return [];
  const views: OfferView[] = [];
  for (const o of await readOffers()) {
    const d = session.saveOffer(o.pageUrl, o.username, o.password, knownSuffix);
    if (d.action === "update") views.push({ origin: o.origin, username: o.username, action: "update", name: String(session.item(d.id).name) });
    else if (d.action === "new") views.push({ origin: o.origin, username: o.username, action: "new", name: d.name });
  }
  return views;
}

/** Saves or updates the item for the offer at `origin`, as vault-client decides it now. */
export async function acceptOffer(origin: string): Promise<void> {
  const offer = (await readOffers()).find((o) => o.origin === origin);
  if (offer === undefined) throw new UserError("no_offer", "That offer is no longer pending.");
  const session = await requireSession();
  const d = session.saveOffer(offer.pageUrl, offer.username, offer.password, knownSuffix);
  if (d.action === "update") {
    const base = session.item(d.id);
    const login = (base.login ?? {}) as Record<string, unknown>;
    const edited = { ...base, login: { ...login, password: offer.password } };
    await edit((s, onDisk, deviceId, now) => s.update(onDisk, deviceId, now, d.id, base, edited));
  } else if (d.action === "new") {
    await edit((s, onDisk, deviceId, now) =>
      s.add(onDisk, deviceId, now, {
        type: "login", name: d.name, username: offer.username, password: offer.password,
        uris: [{ uri: d.uri, match: d.match }],
      }),
    );
  }
  await dismissOffer(origin);
}

export async function dismissOffer(origin: string): Promise<void> {
  await removeOffer(origin);
  await updateOfferBadge();
}

/** The toolbar button's default badge shows the number of pending offers. */
export async function updateOfferBadge(): Promise<void> {
  const n = (await readOffers()).length;
  await browser.action.setBadgeText({ text: n === 0 ? "" : `+${n}` });
}
