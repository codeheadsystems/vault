// The background script's entry point. Every listener is registered synchronously at the top level,
// so an event that wakes a suspended event page is delivered to it.

import { stateSummary } from "vault-wasm";
import {
  isExtensionPage, isTopFrameContentScript, parseRequest, parseSaveSubmit, USER_ACTIONS,
  type Request, type Response, type Sender,
} from "../shared/messages.ts";
import { readSettings, writeSettings } from "../shared/session.ts";
import { loadWasm } from "../shared/wasm.ts";
import {
  ALARM_CLIPBOARD, ALARM_SYNC, edit, getSession, lock, lockIfIdle, recordActivity,
  reload, requireSession, startAlarms, store, unlock, UserError,
} from "./agent.ts";
import { clearClipboard, copy } from "./clipboard.ts";
import { activeTab, candidatesFor, fillFromPopup, fillFromShortcut, generate, generateIntoField, setPickBadge } from "./fill.ts";
import { acceptOffer, dismissOffer, listOffers, onSubmit, updateOfferBadge } from "./offers.ts";
import { requestSync, syncIssue } from "./sync.ts";

const MENU_FILL = "fill";
const MENU_GENERATE = "generate";
const DEFAULT_GENERATE = {
  kind: "password", length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false,
} as const;

const extensionBase = browser.runtime.getURL("");

// Work for one instance runs one step at a time: the start-of-instance idle check finishes before
// any request is handled.
const started = (async () => {
  await lockIfIdle().catch(() => {});
  await navigator.storage.persist().catch(() => false);
})();

browser.runtime.onMessage.addListener((msg: unknown, sender: browser.runtime.MessageSender) => {
  const s = sender as Sender;
  if (!isExtensionPage(s, browser.runtime.id, extensionBase)) {
    // A content script, in any frame. Every one gets the same reply, whatever it sent and whatever
    // state the vault is in, so a page learns nothing; only the save watcher's message from a top
    // frame has any effect.
    const submit = parseSaveSubmit(msg);
    if (submit !== null && isTopFrameContentScript(s, browser.runtime.id)) {
      void started.then(() => onSubmit(s.url as string, submit.username, submit.password)).catch(() => {});
    }
    return Promise.resolve({});
  }
  const request = parseRequest(msg);
  if (request === null) return Promise.resolve(failure("bad_request", "The request is malformed."));
  return started.then(() => handle(request)).then(
    (value): Response => ({ ok: true, value }),
    (e: unknown): Response => (e instanceof UserError ? failure(e.code, e.message) : failure(codeOf(e), String((e as Error)?.message ?? e))),
  );
});

browser.alarms.onAlarm.addListener((alarm) => {
  void started.then(async () => {
    if (alarm.name === ALARM_CLIPBOARD) {
      try {
        await clearClipboard();
      } catch {
        // The clipboard may be unavailable; the idle check below still runs.
      }
    }
    await lockIfIdle();
    if (alarm.name === ALARM_SYNC && (await getSession()) !== null) await requestSync();
  }).catch(() => {});
});

browser.commands.onCommand.addListener((name: string, tab?: browser.tabs.Tab) => {
  if (name !== "fill") return;
  void started.then(async () => {
    await lockIfIdle();
    const tabId = tab?.id ?? (await activeTab()).id!;
    await recordActivity();
    await fillFromShortcut(tabId);
  }).catch(() => {});
});

browser.menus.onClicked.addListener((info: browser.menus.OnClickData, tab?: browser.tabs.Tab) => {
  if (tab?.id === undefined) return;
  const tabId = tab.id;
  void started.then(async () => {
    await lockIfIdle();
    await recordActivity();
    if (info.menuItemId === MENU_FILL) await fillFromShortcut(tabId);
    else if (info.menuItemId === MENU_GENERATE) await generateIntoField(tabId, DEFAULT_GENERATE, info.frameId ?? null);
  }).catch(() => {});
});

browser.tabs.onUpdated.addListener((tabId: number, change: browser.tabs._OnUpdatedChangeInfo) => {
  // A pick offered on the toolbar button belongs to the page it was offered for.
  if (change.url !== undefined) void setPickBadge(tabId, 0).catch(() => {});
});

function createMenus(): void {
  browser.menus.removeAll().then(() => {
    browser.menus.create({ id: MENU_FILL, title: "Fill login from vault", contexts: ["editable", "password"] });
    browser.menus.create({ id: MENU_GENERATE, title: "Generate password with vault", contexts: ["password"] });
  });
}
browser.runtime.onInstalled.addListener(createMenus);
browser.runtime.onStartup.addListener(createMenus);

function failure(code: string, message: string): Response {
  return { ok: false, code, message };
}

function codeOf(e: unknown): string {
  const code = (e as { code?: unknown })?.code;
  return typeof code === "string" ? code : "error";
}

async function handle(request: Request): Promise<unknown> {
  await lockIfIdle();
  if (USER_ACTIONS.has(request.type)) await recordActivity();
  switch (request.type) {
    case "status":
      return status();
    case "unlock": {
      const r = await unlock(request.password);
      await updateOfferBadge();
      return r;
    }
    case "lock":
      await lock();
      return null;
    case "list":
      return (await requireSession()).list(request.text === "" ? undefined : { text: request.text });
    case "item":
      return (await requireSession()).item(request.id);
    case "copy":
      await copy(request.id, request.field);
      return null;
    case "candidates": {
      const tab = await activeTab();
      const { url, candidates } = await candidatesFor(tab.id!);
      return { host: hostOf(url), candidates };
    }
    case "fill":
      return fillFromPopup((await activeTab()).id!, request.id, request.confirmedHost);
    case "add": {
      const r = await edit((s, onDisk, deviceId, now) => s.add(onDisk, deviceId, now, request.item));
      void requestSync();
      return { id: r.id };
    }
    case "update":
      await edit((s, onDisk, deviceId, now) => s.update(onDisk, deviceId, now, request.id, request.base, request.edited));
      void requestSync();
      return null;
    case "remove":
      await edit((s, onDisk, deviceId, now) => s.remove(onDisk, deviceId, now, request.id));
      void requestSync();
      return null;
    case "generate":
      return generate(request.options);
    case "generateIntoField":
      return generateIntoField((await activeTab()).id!, request.options, null);
    case "offerSave":
      await acceptOffer(request.origin);
      void requestSync();
      return null;
    case "offerDismiss":
      await dismissOffer(request.origin);
      return null;
    case "syncNow":
      await requireSession();
      await requestSync();
      return status();
    case "stateChanged":
      await reload();
      if ((await getSession()) !== null) await startAlarms();
      return null;
    case "setSettings":
      await writeSettings(request.settings);
      return null;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

async function status(): Promise<unknown> {
  const [state, config, settings] = await Promise.all([store.readState(), store.readConfig(), readSettings()]);
  if (state === null || config === null) return { configured: false, unlocked: false, settings };
  await loadWasm();
  const unlocked = (await getSession()) !== null;
  return {
    configured: true,
    unlocked,
    server: config.url,
    summary: stateSummary(state),
    syncIssue: await syncIssue(),
    offers: unlocked ? await listOffers() : [],
    settings,
  };
}
