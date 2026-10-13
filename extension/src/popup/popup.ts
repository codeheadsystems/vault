// The popup (docs/firefox.md, Components): unlock, search, view, copy, fill, add, and quick edits;
// the toolbar badge's candidate picker; pending save offers; and the sync state. The popup has no
// vault of its own: every action is a request to the background script, which holds the session.

import type { Candidate, ItemEntry, NewItem, StateSummary } from "vault-wasm";
import type { GenerateOptions, Settings } from "../shared/messages.ts";
import { errorText, h, openVaultPage, replace, send } from "../shared/ui.ts";

interface OfferView { origin: string; username: string; action: "update" | "new"; name: string }
interface Status {
  configured: boolean;
  unlocked: boolean;
  server?: string;
  summary?: StateSummary;
  syncIssue?: { code: string; message: string } | null;
  offers?: OfferView[];
  settings: Settings;
}
type FillOutcome =
  | { kind: "filled"; frames: number }
  | { kind: "confirm"; reason: "not_candidate" | "local_http"; host: string }
  | { kind: "refused"; reason: "http_page"; host: string }
  | { kind: "nothing"; reason: string };
type Item = Record<string, unknown> & { id: string; type: string; name: string; login?: { username: string; password: string; uris: { uri: string; match: string }[] }; notes?: string; folder?: string };

const DEFAULT_PASSWORD: GenerateOptions = {
  kind: "password", length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false,
};

const app = document.getElementById("app")!;
const flash = (text: string, kind: "error" | "info" = "error") => {
  const el = h("p", { class: `flash ${kind}`, role: kind === "error" ? "alert" : "status" }, text);
  app.prepend(el);
  setTimeout(() => el.remove(), 6000);
};

async function main(): Promise<void> {
  let status: Status;
  try {
    status = await send<Status>({ type: "status" });
  } catch (e) {
    replace(app, h("p", { class: "flash error" }, errorText(e)));
    return;
  }
  if (!status.configured) return renderSetup();
  if (!status.unlocked) return renderLocked();
  return renderUnlocked(status);
}

function renderSetup(): void {
  replace(
    app,
    h("h1", {}, "vault"),
    h("p", {}, "This browser has no vault yet."),
    h("button", { on: { click: () => (openVaultPage("setup"), window.close()) } }, "Set up vault"),
  );
}

function renderLocked(): void {
  const password = h("input", { type: "password", id: "password", autocomplete: "current-password", placeholder: "Master password", autofocus: true });
  const button = h("button", { type: "submit", id: "unlock" }, "Unlock");
  const form = h("form", {
    on: {
      submit: async (e) => {
        e.preventDefault();
        button.disabled = true;
        button.textContent = "Unlocking…";
        try {
          await send({ type: "unlock", password: password.value });
          password.value = "";
          await main();
        } catch (err) {
          button.disabled = false;
          button.textContent = "Unlock";
          password.select();
          flash(errorText(err));
          if ((err as { code?: string }).code === "needs_vault_page") {
            app.append(h("button", { on: { click: () => (openVaultPage("resolve"), window.close()) } }, "Open the vault page"));
          }
        }
      },
    },
  }, password, button);
  replace(app, h("h1", {}, "vault is locked"), form);
  password.focus();
}

function syncLine(status: Status): HTMLElement | null {
  const stopped = status.summary?.stopped;
  if (stopped) {
    const action = stopped.reason === "integrity" ? "Run recovery" : stopped.reason === "token" ? "Replace the server token" : "Resolve the credential change";
    return h("div", { class: "flash error", id: "stopped" },
      `Sync stopped (${stopped.code}). `,
      h("a", { href: "#", on: { click: (e) => (e.preventDefault(), openVaultPage("resolve"), window.close()) } }, `${action} in the vault page`), ".");
  }
  if (status.syncIssue) {
    return h("div", { class: "flash error", id: "sync-issue" }, status.syncIssue.message,
      status.syncIssue.code === "host_permission"
        ? h("a", { href: "#", on: { click: (e) => (e.preventDefault(), openVaultPage("server"), window.close()) } }, " Open the vault page.")
        : null);
  }
  const last = status.summary?.lastSync;
  return h("p", { class: "muted", id: "sync-state" },
    status.summary?.unpushed ? "Changes not yet synced. " : "",
    last ? `Synced ${new Date(last).toLocaleTimeString()}.` : "Not synced yet.");
}

function renderUnlocked(status: Status): void {
  const search = h("input", { type: "search", id: "search", placeholder: "Search", autofocus: true });
  const results = h("ul", { class: "items", id: "results" });
  const pageSection = h("section", { id: "page-candidates" });
  const offersSection = h("section", { id: "offers" });
  const runSearch = async () => {
    try {
      const items = await send<ItemEntry[]>({ type: "list", text: search.value });
      replace(results, ...items.map((i) => itemRow(i)));
      if (items.length === 0) results.append(h("li", { class: "muted" }, "No items."));
    } catch (e) {
      flash(errorText(e));
    }
  };
  search.addEventListener("input", () => void runSearch());

  replace(
    app,
    h("header", {},
      h("h1", {}, "vault"),
      h("button", { id: "sync-now", title: "Sync now", on: { click: async () => { try { await send({ type: "syncNow" }); await main(); } catch (e) { flash(errorText(e)); } } } }, "Sync"),
      h("button", { id: "add", on: { click: () => renderEdit(null) } }, "Add"),
      h("button", { id: "generate", on: { click: () => renderGenerator() } }, "Generate"),
      h("button", { id: "lock", on: { click: async () => { await send({ type: "lock" }); await main(); } } }, "Lock"),
      h("button", { id: "open-page", title: "Vault page", on: { click: () => (openVaultPage(), window.close()) } }, "⚙"),
    ),
    syncLine(status),
    offersSection,
    pageSection,
    search,
    results,
  );
  renderOffers(offersSection, status.offers ?? []);
  void renderCandidates(pageSection);
  void runSearch();
  search.focus();
}

function renderOffers(section: HTMLElement, offers: OfferView[]): void {
  if (offers.length === 0) return replace(section);
  replace(section, h("h2", {}, "Save logins"), ...offers.map((o) => h("div", { class: "offer", dataset: { origin: o.origin } },
    h("p", {}, o.action === "update" ? `Update the password of ${o.name}` : `Save a login for ${o.name}`, o.username ? ` (${o.username})` : "", "?"),
    h("button", { class: "offer-save", on: { click: async () => { try { await send({ type: "offerSave", origin: o.origin }); await main(); flash("Saved.", "info"); } catch (e) { flash(errorText(e)); } } } }, o.action === "update" ? "Update" : "Save"),
    h("button", { class: "offer-dismiss", on: { click: async () => { await send({ type: "offerDismiss", origin: o.origin }); await main(); } } }, "Not now"),
  )));
}

async function renderCandidates(section: HTMLElement): Promise<void> {
  let found: { host: string; candidates: Candidate[] };
  try {
    found = await send({ type: "candidates" });
  } catch {
    return replace(section);
  }
  if (found.candidates.length === 0) return replace(section);
  replace(section, h("h2", {}, `Logins for ${found.host}`), h("ul", { class: "items" }, ...found.candidates.map((c) =>
    h("li", { class: "candidate", dataset: { id: c.id } },
      h("span", { class: "name" }, c.name), h("span", { class: "muted" }, ` ${c.username}`),
      c.outcome === "confirm" ? h("span", { class: "warn", title: "This page uses http; the login is for https" }, " http") : null,
      h("button", { class: "fill", on: { click: () => void fill(c.id, null) } }, "Fill")),
  )));
}

async function fill(id: string, confirmedHost: string | null): Promise<void> {
  try {
    const r = await send<FillOutcome>({ type: "fill", id, confirmedHost });
    if (r.kind === "filled") return window.close();
    if (r.kind === "confirm") {
      const question = r.reason === "local_http"
        ? `${r.host} is a local page served over http, and this login is for https. Fill it anyway?`
        : `This login is not saved for ${r.host}. Fill it on ${r.host} anyway?`;
      return renderConfirm(question, () => void fill(id, r.host));
    }
    if (r.kind === "refused") return flash(`${r.host} is not a secure page, and this login is not saved for it, so vault does not fill it.`);
    flash(r.reason === "no_fields" ? "No login fields found on this page." : `Nothing filled (${r.reason}).`);
  } catch (e) {
    flash(errorText(e));
  }
}

function renderConfirm(question: string, yes: () => void): void {
  const back = () => void main();
  replace(app, h("div", { class: "confirm", id: "confirm" }, h("p", {}, question),
    h("button", { id: "confirm-yes", on: { click: yes } }, "Fill"),
    h("button", { id: "confirm-no", on: { click: back } }, "Cancel")));
}

function itemRow(i: ItemEntry): HTMLElement {
  return h("li", { class: "item", dataset: { id: i.id } },
    h("a", { href: "#", on: { click: (e) => (e.preventDefault(), void renderItem(i.id)) } },
      h("span", { class: "name" }, i.name), h("span", { class: "muted" }, i.username ? ` ${i.username}` : "")),
    i.type === "login" ? h("button", { class: "copy-username", title: "Copy username", on: { click: () => void copy(i.id, "username") } }, "User") : null,
    i.type === "login" ? h("button", { class: "copy-password", title: "Copy password", on: { click: () => void copy(i.id, "password") } }, "Pass") : null,
  );
}

async function copy(id: string, field: "username" | "password"): Promise<void> {
  try {
    await send({ type: "copy", id, field });
    flash(`Copied the ${field}; the clipboard clears in 45 seconds.`, "info");
  } catch (e) {
    flash(errorText(e));
  }
}

async function renderItem(id: string): Promise<void> {
  let item: Item;
  try {
    item = await send<Item>({ type: "item", id });
  } catch (e) {
    return flash(errorText(e));
  }
  const password = h("code", { class: "secret", id: "item-password" }, "••••••••");
  let shown = false;
  replace(app,
    h("header", {}, h("button", { on: { click: () => void main() } }, "←"), h("h1", {}, item.name)),
    item.login ? h("dl", {},
      h("dt", {}, "Username"), h("dd", { id: "item-username" }, item.login.username, " ", h("button", { on: { click: () => void copy(id, "username") } }, "Copy")),
      h("dt", {}, "Password"), h("dd", {}, password, " ",
        h("button", { id: "toggle-password", on: { click: () => { shown = !shown; password.textContent = shown ? item.login!.password : "••••••••"; } } }, "Show"),
        h("button", { on: { click: () => void copy(id, "password") } }, "Copy")),
      h("dt", {}, "Websites"), ...item.login.uris.map((u) => h("dd", {}, u.uri))) : null,
    item.notes ? h("pre", { class: "notes" }, item.notes) : null,
    h("footer", {},
      item.type === "login" ? h("button", { id: "item-fill", on: { click: () => void fill(id, null) } }, "Fill") : null,
      h("button", { id: "item-edit", on: { click: () => renderEdit(item) } }, "Edit"),
      h("button", { id: "item-delete", on: { click: () => renderConfirmDelete(item) } }, "Delete")),
  );
}

function renderConfirmDelete(item: Item): void {
  replace(app, h("p", {}, `Delete ${item.name}?`),
    h("button", { id: "delete-yes", on: { click: async () => { try { await send({ type: "remove", id: item.id }); await main(); } catch (e) { flash(errorText(e)); } } } }, "Delete"),
    h("button", { on: { click: () => void renderItem(item.id) } }, "Cancel"));
}

/** The add form (item null) or a quick edit of a login or note. */
function renderEdit(item: Item | null): void {
  const field = (id: string, label: string, value: string, type = "text") => {
    const input = h("input", { id, type, value });
    return { input, row: h("label", {}, label, input) };
  };
  const name = field("edit-name", "Name", item?.name ?? "");
  const username = field("edit-username", "Username", item?.login?.username ?? "");
  const password = field("edit-password", "Password", item?.login?.password ?? "", "password");
  const reveal = h("button", { type: "button", id: "edit-reveal", on: { click: () => {
    const hidden = password.input.type === "password";
    password.input.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "Hide" : "Show";
  } } }, "Show");
  const uri = field("edit-uri", "Website", item?.login?.uris[0]?.uri ?? "");
  const folder = field("edit-folder", "Folder", String(item?.folder ?? ""));
  const notes = h("textarea", { id: "edit-notes" }, String(item?.notes ?? ""));
  const isNote = item !== null && item.type === "note";
  const generate = h("button", { type: "button", id: "edit-generate", on: { click: async () => {
    try { password.input.value = (await send<{ value: string }>({ type: "generate", options: DEFAULT_PASSWORD })).value; } catch (e) { flash(errorText(e)); }
  } } }, "Generate");
  const save = async (e: Event) => {
    e.preventDefault();
    try {
      if (item === null) {
        const newItem: NewItem = { type: "login", name: name.input.value.trim(), folder: folder.input.value, notes: notes.value, username: username.input.value, password: password.input.value };
        if (uri.input.value.trim() !== "") newItem.uris = [{ uri: uri.input.value.trim(), match: "base_domain" }];
        await send({ type: "add", item: newItem });
      } else {
        const edited: Item = structuredClone(item);
        edited.name = name.input.value.trim();
        edited.folder = folder.input.value;
        edited.notes = notes.value;
        if (edited.login) {
          edited.login.username = username.input.value;
          edited.login.password = password.input.value;
          const uris = edited.login.uris.slice();
          const u = uri.input.value.trim();
          if (u === "") uris.splice(0, 1);
          else if (uris.length === 0) uris.push({ uri: u, match: "base_domain" });
          else uris[0] = { ...uris[0], uri: u };
          edited.login.uris = uris;
        }
        await send({ type: "update", id: item.id, base: item, edited });
      }
      await main();
    } catch (err) {
      flash(errorText(err));
    }
  };
  replace(app,
    h("header", {}, h("button", { on: { click: () => void main() } }, "←"), h("h1", {}, item === null ? "Add a login" : `Edit ${item.name}`)),
    h("form", { id: "edit-form", on: { submit: save } },
      name.row,
      isNote ? null : username.row,
      isNote ? null : h("div", { class: "row" }, password.row, reveal, generate),
      isNote ? null : uri.row,
      folder.row,
      h("label", {}, "Notes", notes),
      h("button", { type: "submit", id: "edit-save" }, "Save")),
  );
  name.input.focus();
}

function renderGenerator(): void {
  const length = h("input", { type: "number", id: "gen-length", min: "8", max: "128", value: "20" });
  const symbols = h("input", { type: "checkbox", id: "gen-symbols", checked: true });
  const out = h("output", { id: "gen-value" });
  const options = (): GenerateOptions => ({ ...DEFAULT_PASSWORD, length: Number(length.value) || 20, symbols: symbols.checked } as GenerateOptions);
  const run = async () => {
    try {
      const r = await send<{ value: string; bits: number }>({ type: "generate", options: options() });
      out.textContent = r.value;
      out.title = `${Math.round(r.bits)} bits`;
    } catch (e) {
      flash(errorText(e));
    }
  };
  replace(app,
    h("header", {}, h("button", { on: { click: () => void main() } }, "←"), h("h1", {}, "Generate a password")),
    h("label", {}, "Length ", length), h("label", {}, symbols, " Symbols"),
    h("p", {}, out),
    h("button", { on: { click: () => void run() } }, "New"),
    h("button", { id: "gen-fill", on: { click: async () => {
      try {
        const r = await send<FillOutcome>({ type: "generateIntoField", options: options() });
        if (r.kind === "filled") window.close();
        else flash("No password field found on this page.");
      } catch (e) { flash(errorText(e)); }
    } } }, "Generate into the page"),
  );
  void run();
}

void main();
