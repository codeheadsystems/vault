// The vault page (docs/firefox.md, Components and Setup): a full-tab extension page for setup,
// credential changes, recovery, restore, the server's access, and turning on save offers. It runs
// procedures that can wait on prompts in its own WASM instance, commits under the state lock, and
// tells the background script when the state changed.

import {
  decodeSecretKey, parseRevisions, parseSetupText, Procedure, Session, stateSummary,
  type Input, type PasswdChange, type Prompt, type State,
} from "vault-wasm";
import { drive, type DoneStep, type SaveStep } from "../shared/drive.ts";
import { readSettings, readVaultKey, storeVaultKey } from "../shared/session.ts";
import { fingerprintForms, permissionFor } from "../shared/setup.ts";
import { Store, unhex, webLock, type Config } from "../shared/storage.ts";
import { apiUrl, probe, send as sendRequest, type Server } from "../shared/transport.ts";
import { errorText, h, replace, send } from "../shared/ui.ts";
import { loadWasm } from "../shared/wasm.ts";

const store = new Store(indexedDB, webLock);
const app = document.getElementById("app")!;
const WATCHER_ID = "save-watcher";
const ALL_SITES = "*://*/*";

function section(id: string, title: string, ...children: (Node | string | null)[]): HTMLElement {
  return h("section", { class: "step", id }, h("h2", {}, title), ...children);
}

function message(el: HTMLElement, text: string, kind: "error" | "info" = "error"): void {
  replace(el, text ? h("p", { class: `flash ${kind}`, role: kind === "error" ? "alert" : "status" }, text) : null);
}

// ---- Prompts -------------------------------------------------------------------------------

const promptArea = h("div", { id: "prompt-area" });

/** Shows a prompt from a procedure and resolves with the user's answer. */
function ask(prompt: Prompt): Promise<Input> {
  return new Promise((resolve) => {
    const err = h("div");
    const answer = (input: Input) => {
      replace(promptArea);
      resolve(input);
    };
    const decline = h("button", { type: "button", id: "prompt-decline", on: { click: () => answer({ type: "answer", declined: true }) } }, "Cancel");
    const pw = (id: string, label: string) => {
      const input = h("input", { type: "password", id, autocomplete: "current-password" });
      return { input, row: h("label", {}, label, input) };
    };
    let body: (Node | null)[] = [];
    let submit: () => Input | null = () => null;
    switch (prompt.kind) {
      case "master_password": {
        const p = pw("prompt-password", "Master password");
        const why: Record<string, string> = {
          unlock: "Unlock the vault.",
          credentials_changed: "Another device changed the master password or the secret key. Enter the new master password.",
          pending_secret_key: "Enter the master password to find out whether the new secret key took effect.",
          recovery: "Enter the master password that was in use for this revision.",
          revision: "Enter the master password that opens this revision.",
        };
        body = [h("p", {}, why[prompt.purpose] ?? ""), prompt.failed > 0 ? h("p", { class: "flash error" }, "Wrong master password.") : null, p.row];
        submit = () => ({ type: "answer", password: p.input.value });
        break;
      }
      case "master_password_and_secret_key": {
        const p = pw("prompt-password", "Master password");
        const k = h("input", { type: "text", id: "prompt-secret-key", autocomplete: "off", spellcheck: false });
        const why: Record<string, string> = {
          credentials_changed: "Another device changed the secret key, so the stored one no longer opens the vault. Enter the master password and the secret key from the new emergency kit.",
          recovery: "Enter the master password and the secret key that were in use for this revision.",
          revision: "This revision is under an earlier secret key. Enter the master password and the secret key that open it.",
        };
        body = [h("p", {}, why[prompt.purpose] ?? "Enter the master password and the secret key."), p.row, h("label", {}, "Secret key", k)];
        submit = () => {
          try {
            return { type: "answer", password: p.input.value, secretKey: decodeSecretKey(k.value) };
          } catch (e) {
            message(err, errorText(e));
            return null;
          }
        };
        break;
      }
      case "old_master_password": {
        const p = pw("prompt-password", "Previous master password");
        body = [h("p", {}, "Changes on this device were made under the previous credentials. Enter the previous master password to keep them."), prompt.failed > 0 ? h("p", { class: "flash error" }, "Wrong password.") : null, p.row];
        submit = () => ({ type: "answer", password: p.input.value });
        break;
      }
      case "new_master_password": {
        const p = pw("prompt-new-password", "New master password");
        const r = pw("prompt-new-password-repeat", "Repeat it");
        p.input.autocomplete = "new-password";
        r.input.autocomplete = "new-password";
        body = [prompt.rejected ? h("p", { class: "flash error" }, `That password breaks a rule: ${prompt.rejected}.`) : null, p.row, r.row];
        submit = () => {
          if (p.input.value !== r.input.value) {
            message(err, "The two passwords differ.");
            return null;
          }
          return { type: "answer", password: p.input.value };
        };
        break;
      }
      case "secret_key": {
        const k = h("input", { type: "text", id: "prompt-secret-key", autocomplete: "off", spellcheck: false });
        body = [h("label", {}, "Secret key (VLT1-…)", k)];
        submit = () => {
          try {
            return { type: "answer", secretKey: decodeSecretKey(k.value) };
          } catch (e) {
            message(err, errorText(e));
            return null;
          }
        };
        break;
      }
      case "kit_vault_id": {
        const v = h("input", { type: "text", id: "prompt-vault-id", autocomplete: "off", spellcheck: false });
        body = [h("label", {}, "Vault ID from the emergency kit (optional)", v)];
        submit = () => {
          const t = v.value.trim().toLowerCase();
          if (t === "") return { type: "answer", vaultId: null };
          if (!/^[0-9a-f]{32}$/.test(t)) {
            message(err, "A vault ID is 32 hex characters.");
            return null;
          }
          return { type: "answer", vaultId: unhex(t) };
        };
        break;
      }
      case "confirm": {
        replace(promptArea, h("div", { id: "prompt" }, h("p", {}, prompt.description),
          h("button", { id: "prompt-yes", on: { click: () => answer({ type: "answer", confirmed: true }) } }, "Yes"),
          h("button", { id: "prompt-no", on: { click: () => answer({ type: "answer", confirmed: false }) } }, "No")));
        return;
      }
    }
    const form = h("form", { id: "prompt", on: { submit: (e) => {
      e.preventDefault();
      const input = submit();
      if (input !== null) answer(input);
    } } }, ...body, err, h("button", { type: "submit", id: "prompt-ok" }, "Continue"), decline);
    replace(promptArea, form);
    form.querySelector("input")?.focus();
  });
}

/** Shows the new emergency kit and resolves once the user typed the secret key's last group. */
function showKit(step: SaveStep, server: string): Promise<void> {
  return new Promise((resolve) => {
    const last = step.kit.split("-").pop() ?? "";
    const typed = h("input", { type: "text", id: "kit-confirm", autocomplete: "off" });
    const err = h("div");
    replace(promptArea, h("form", { id: "prompt", on: { submit: (e) => {
      e.preventDefault();
      if (typed.value.trim().toUpperCase() !== last) return message(err, "That is not the last group of the secret key.");
      replace(promptArea);
      resolve();
    } } },
    h("p", {}, "Write down or print this emergency kit. A new device needs it and the master password."),
    h("pre", { class: "kit" }, `Secret key:  ${step.kit}\nServer:      ${server}\nVault ID:    ${step.vaultId}`),
    h("label", {}, "To confirm you kept it, type the last group of the secret key", typed), err,
    h("button", { type: "submit", id: "kit-ok" }, "Continue")));
    typed.focus();
  });
}

// ---- The page's own unlocked state --------------------------------------------------------

/**
 * Sessions and procedures this page holds open. When the vault locks anywhere (the vault key
 * leaves storage.session), every one is locked and freed at once, and the page says so.
 */
const held = new Set<() => void>();
let lockEpoch = 0;

/** Holds `obj` until the returned release is called or the vault locks; frees it exactly once. */
function hold(obj: { free(): void; lock?(): void }): () => void {
  let done = false;
  const dispose = () => {
    if (done) return;
    done = true;
    held.delete(dispose);
    obj.lock?.();
    obj.free();
  };
  held.add(dispose);
  return dispose;
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "session" || !("vk" in changes) || changes.vk.newValue !== undefined) return;
  lockEpoch++;
  for (const dispose of [...held]) {
    try {
      dispose();
    } catch {
      // Already unusable.
    }
  }
  if (document.getElementById("page-locked") === null) {
    app.prepend(h("p", { class: "flash error", id: "page-locked", role: "alert" },
      "The vault locked. Anything this page had open is closed; unlock from the toolbar button, then reload this page."));
  }
});

/** Whether the vault is unlocked now; the key read for the check is zeroed. */
async function unlockedNow(): Promise<boolean> {
  const key = await readVaultKey();
  key?.fill(0);
  return key !== null;
}

// ---- Running procedures --------------------------------------------------------------------

async function keysFor(state: State): Promise<{ vaultKey?: Uint8Array; secretKey?: Uint8Array; pendingSecretKey?: Uint8Array }> {
  const { current, pending } = await store.readSecretKeys(stateSummary(state).vaultId);
  return { vaultKey: (await readVaultKey()) ?? undefined, secretKey: current ?? undefined, pendingSecretKey: pending ?? undefined };
}

function zero(keys: { vaultKey?: Uint8Array; secretKey?: Uint8Array; pendingSecretKey?: Uint8Array }): void {
  keys.vaultKey?.fill(0);
  keys.secretKey?.fill(0);
  keys.pendingSecretKey?.fill(0);
}

/**
 * Runs a procedure that started from `started`, with prompts in this page, commits its result under
 * the state lock, stores the vault key it ends with, and tells the background script.
 *
 * The result is committed even when the vault locked meanwhile, because it may already be on the
 * server (a credential change, for example) and the commit rule keeps the state consistent. But a
 * procedure that started unlocked does not unlock the vault again after a lock: its key is
 * discarded and the user unlocks as usual.
 */
async function run(proc: Procedure, started: State, server: Server, startedUnlocked: boolean,
  extra?: (host: { writeConfig(c: Config): void }) => void): Promise<DoneStep> {
  const epoch = lockEpoch;
  const release = hold(proc);
  let relocked = false;
  let done: DoneStep;
  try {
    let from = started;
    done = await drive(proc, server, {
      prompt: ask,
      save: async (step) => {
        await showKit(step, server.url);
        await store.commit((onDisk, host) => proc.applySave(from, onDisk ?? from, Date.now(), host));
        from = step.state;
      },
    });
    const result = done;
    await store.commit((onDisk, host) => {
      const applied = proc.apply(from, onDisk ?? from, false, Date.now(), host);
      if (result.ok && extra) extra(host);
      return applied;
    });
    const key = proc.vaultKey();
    if (key !== null) {
      relocked = startedUnlocked && (lockEpoch !== epoch || !(await unlockedNow()));
      if (!relocked) await storeVaultKey(key, Date.now());
      key.fill(0);
    }
  } finally {
    release();
  }
  await send({ type: "stateChanged" }).catch(() => {});
  if (relocked) throw new Error("The vault locked while this ran. The change is saved; unlock again from the toolbar button.");
  return done;
}

// ---- Setup (FF-8) --------------------------------------------------------------------------

async function renderSetup(): Promise<void> {
  const status = h("div");
  const text = h("textarea", { id: "setup-text", rows: 3, placeholder: "vault://setup?url=…&token=…", spellcheck: false });
  const next = h("button", { id: "setup-continue" }, "Continue");
  const step1 = section("setup-1", "1. Setup text", h("p", {}, "Paste the setup text that `vault serve token add` printed."), text, next, status);
  const step2 = section("setup-2", "2. Server certificate");
  const step3 = section("setup-3", "3. Secret key and master password");
  step2.hidden = step3.hidden = true;
  replace(app, h("h1", {}, "Set up vault"), step1, step2, step3, promptArea);

  next.addEventListener("click", () => {
    let parsed: ReturnType<typeof parseSetupText>;
    try {
      parsed = parseSetupText(text.value);
    } catch (e) {
      return message(status, errorText(e));
    }
    const permission = permissionFor(parsed.url);
    // The permission request must be the first await of the click, which Firefox requires.
    void browser.permissions.request({ origins: [permission] }).then(async (granted) => {
      if (!granted) return message(status, `vault needs access to ${permission} to reach the server.`);
      step1.classList.add("done");
      next.disabled = true;
      const server = { url: parsed.url, token: parsed.token };
      await renderCertificate(step2, server, parsed.fp, parsed.loopbackHttp);
      renderCredentials(step3, { ...server, fp: parsed.fp, permission });
    });
  });
  text.focus();
}

/** A test request without the token: any response, a 401 included, proves that TLS succeeded. The
 * token goes only with the procedures' own requests. */
function reachable(server: Server): Promise<boolean> {
  return probe(server.url);
}

/** Step 2: the certificate exception for an https server with a fingerprint. */
function renderCertificate(el: HTMLElement, server: Server, fp: string | null, loopbackHttp: boolean): Promise<void> {
  el.hidden = false;
  const status = h("div");
  if (loopbackHttp) {
    replace(el, h("h2", {}, "2. Server certificate"), h("p", {}, "The server runs on this machine over http; no certificate is involved."));
    el.classList.add("done");
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const finish = () => {
      el.classList.add("done");
      resolve();
    };
    const check = async () => {
      if (fp === null) {
        if (await reachable(server)) return finish();
        return message(status, "The server's certificate is not publicly trusted, and the setup text has no fingerprint. Ask for setup text with the fingerprint.");
      }
      if (await reachable(server)) {
        replace(el, h("h2", {}, "2. Server certificate"),
          h("p", { class: "flash error", id: "preexisting-exception" },
            `This Firefox profile already trusts a certificate for ${new URL(server.url).host}, perhaps through an earlier exception that nobody compared, so vault cannot check the fingerprint. `,
            "Consider removing that exception in Firefox's certificate manager (Settings, Privacy & Security, Certificates, View Certificates, Servers) and checking again."),
          h("button", { id: "cert-check-again", on: { click: () => void check() } }, "Check again"),
          h("button", { id: "cert-continue-anyway", on: { click: finish } }, "Continue anyway"), status);
        return;
      }
      const forms = fingerprintForms(fp);
      const serverPage = apiUrl(server.url, "/v1/vault");
      let tab = await browser.tabs.create({ url: serverPage, active: true });
      /** The server's tab, opened again when the user closed it. */
      const showTab = async () => {
        const open = await browser.tabs.get(tab.id!).then(() => true, () => false);
        if (open) await browser.tabs.update(tab.id!, { active: true });
        else tab = await browser.tabs.create({ url: serverPage, active: true });
      };
      replace(el, h("h2", {}, "2. Server certificate"),
        h("p", {}, "A new tab shows Firefox's warning for the server. Choose Advanced, then View Certificate, and compare its SHA-256 fingerprint with this one:"),
        h("p", { class: "fingerprint", id: "fp-colons" }, forms.colons),
        h("p", { class: "fingerprint muted", id: "fp-hex" }, forms.hex),
        h("p", {}, "When they match, go back to the tab, choose Accept the Risk and Continue, and then confirm here. Nothing the tab shows is trusted."),
        h("button", { id: "cert-confirm", on: { click: async () => {
          if (await reachable(server)) {
            // Only now: the exception is in place, and the tab has nothing more to show.
            await browser.tabs.remove(tab.id!).catch(() => {});
            finish();
          } else {
            message(status, "vault still cannot reach the server. Accept the exception in the server's tab, after comparing the fingerprints, and confirm again.");
          }
        } } }, "The fingerprints match and I accepted the exception"),
        h("button", { id: "cert-show-tab", on: { click: () => void showTab() } }, "Show the server's tab"),
        status);
    };
    replace(el, h("h2", {}, "2. Server certificate"), h("p", {}, "Checking the server…"), status);
    void check();
  });
}

/** Steps 3 and 4: the secret key and the master password, through the setup procedure. */
function renderCredentials(el: HTMLElement, server: Server & { fp: string | null; permission: string }): void {
  el.hidden = false;
  const key = h("input", { type: "text", id: "setup-secret-key", autocomplete: "off", spellcheck: false, placeholder: "VLT1-…" });
  const vaultId = h("input", { type: "text", id: "setup-vault-id", autocomplete: "off", spellcheck: false });
  const password = h("input", { type: "password", id: "setup-password", autocomplete: "current-password" });
  const status = h("div");
  const go = h("button", { type: "submit", id: "setup-finish" }, "Set up");
  replace(el, h("h2", {}, "3. Secret key and master password"),
    h("form", { on: { submit: (e) => void submit(e).catch((err) => {
      go.disabled = false;
      message(status, errorText(err));
    }) } },
      h("label", {}, "Secret key, from the emergency kit or `vault key show`", key),
      h("label", {}, "Vault ID from the emergency kit (optional)", vaultId),
      h("label", {}, "Master password", password), go, status));
  key.focus();

  async function submit(e: Event): Promise<void> {
    e.preventDefault();
    let secretKey: Uint8Array;
    try {
      secretKey = decodeSecretKey(key.value);
    } catch (err) {
      return message(status, errorText(err));
    }
    const id = vaultId.value.trim().toLowerCase();
    if (id !== "" && !/^[0-9a-f]{32}$/.test(id)) return message(status, "A vault ID is 32 hex characters.");
    go.disabled = true;
    message(status, "Setting up…", "info");
    const proc = Procedure.setup();
    const release = hold(proc);
    try {
      let typed = password.value;
      let done: DoneStep;
      try {
        done = await drive(proc, server, {
          prompt: (p) => {
            if (p.kind === "secret_key") return Promise.resolve({ type: "answer", secretKey: secretKey.slice() });
            if (p.kind === "kit_vault_id") return Promise.resolve({ type: "answer", vaultId: id === "" ? null : unhex(id) });
            if (p.kind === "master_password" && p.failed === 0 && typed !== "") {
              const answer = typed;
              typed = "";
              return Promise.resolve({ type: "answer", password: answer });
            }
            return ask(p);
          },
        });
      } finally {
        secretKey.fill(0);
        password.value = "";
      }
      if (!done.ok) {
        go.disabled = false;
        return message(status, setupError(done.error.code, done.error.message));
      }
      const deviceId = crypto.getRandomValues(new Uint8Array(16));
      await store.commit((onDisk, host) => {
        // Setup has no earlier state; a browser that already holds one replaces its token instead.
        proc.apply(null, onDisk, false, Date.now(), host);
        host.writeConfig({ url: server.url, token: server.token, fp: server.fp, permission: server.permission, deviceId });
      });
      const vk = proc.vaultKey();
      if (vk !== null) {
        await storeVaultKey(vk, Date.now());
        vk.fill(0);
      }
    } finally {
      release();
    }
    await send({ type: "stateChanged" }).catch(() => {});
    replace(app, h("h1", {}, "vault is set up"), h("p", { id: "setup-done" }, "Use the vault button in the toolbar to search, copy, and fill logins."));
  }
}

function setupError(code: string, message: string): string {
  if (code.startsWith("server.token") || code === "token") return "The server refused the token. Ask for new setup text.";
  if (code === "unreachable") return "The server cannot be reached.";
  return message || code;
}

// ---- Configured vault ----------------------------------------------------------------------

async function renderVault(state: State, config: Config): Promise<void> {
  const summary = stateSummary(state);
  const unlocked = await unlockedNow();
  const settings = await readSettings();
  const hasPermission = await browser.permissions.contains({ origins: [config.permission] });
  const watcher = (await browser.scripting.getRegisteredContentScripts({ ids: [WATCHER_ID] })).length > 0;

  const resolveStatus = h("div");
  const resolve = section("resolve", "Sync",
    h("p", { id: "vault-state" }, `Vault ${summary.vaultId}, generation ${summary.generation ?? "none"}. `,
      summary.unpushed ? "Changes not yet synced. " : "", unlocked ? "Unlocked." : "Locked."),
    summary.stopped
      ? h("p", { class: "flash error", id: "stopped" }, `Sync stopped: ${summary.stopped.code}.`)
      : null,
    summary.stopped?.reason === "integrity"
      ? h("button", { id: "run-recover", on: { click: () => void act(resolveStatus, () => recover(state, config)) } }, "Run recovery")
      : summary.stopped?.reason === "token"
        ? h("p", {}, "Paste new setup text under Server below.")
        : h("button", { id: "run-sync", on: { click: () => void act(resolveStatus, () => interactive(state, config, unlocked)) } },
          unlocked ? "Sync now, answering any questions" : "Unlock and sync"),
    resolveStatus);

  const pwStatus = h("div");
  const change = h("select", { id: "passwd-change" },
    h("option", { value: "new-password" }, "A new master password"),
    h("option", { value: "rekey" }, "A new vault key, same password"),
    h("option", { value: "new-secret-key" }, "A new secret key"),
    h("option", { value: "new-secret-key-and-password" }, "A new secret key and a new master password"));
  const passwd = section("passwd", "Credentials", h("p", {}, "Every change re-encrypts the vault under a new vault key."),
    change, h("button", { id: "run-passwd", on: { click: () => void act(pwStatus, async () => {
      const keys = await keysFor(state);
      try {
        const done = await run(Procedure.passwd(state, keys, change.value as PasswdChange), state, config, keys.vaultKey !== undefined);
        return done.ok ? "The credentials are changed." : done.error.message;
      } finally {
        zero(keys);
      }
    }) } }, "Change"), pwStatus);

  const restoreArea = h("div");
  const restore = section("restore", "Restore", h("button", { id: "list-revisions", on: { click: () => void listRevisions(restoreArea, config) } }, "List revisions"), restoreArea);

  const serverStatus = h("div");
  const newSetup = h("textarea", { id: "server-setup-text", rows: 2, placeholder: "New setup text" });
  const server = section("server", "Server",
    h("p", {}, `Server: ${config.url}`),
    hasPermission ? h("p", { id: "permission-ok" }, `vault may reach ${config.permission}.`)
      : h("p", { class: "flash error" }, `vault may not reach ${config.permission}. `,
        h("button", { id: "grant-permission", on: { click: () => void browser.permissions.request({ origins: [config.permission] }).then(() => void main()) } }, "Grant access")),
    h("label", {}, "Replace the token with new setup text for the same server", newSetup),
    h("button", { id: "repair-token", on: { click: () => void act(serverStatus, () => repairToken(state, config, newSetup.value)) } }, "Replace token"),
    serverStatus);

  const offersBox = h("input", { type: "checkbox", id: "save-offers", checked: watcher });
  offersBox.addEventListener("change", () => {
    if (offersBox.checked) {
      // The permission request is the first await of the click.
      void browser.permissions.request({ origins: [ALL_SITES] }).then(async (granted) => {
        if (!granted) {
          offersBox.checked = false;
          return;
        }
        await browser.scripting.registerContentScripts([{
          id: WATCHER_ID, matches: [ALL_SITES], js: ["watcher.js"], runAt: "document_idle", allFrames: false, persistAcrossSessions: true,
        }]);
      });
    } else {
      void browser.scripting.unregisterContentScripts({ ids: [WATCHER_ID] }).then(() => browser.permissions.remove({ origins: [ALL_SITES] }));
    }
  });
  const offers = section("offers", "Save offers",
    h("label", {}, offersBox, " Offer to save or update a login after a login form submits"),
    h("p", { class: "muted" }, "This needs access to every website, so that vault can see a login form submit. vault saves nothing without your confirmation."));

  const idle = h("input", { type: "number", id: "idle-minutes", min: "1", max: "1440", value: String(settings.idleMinutes) });
  const settingsStatus = h("div");
  const prefs = section("settings", "Settings", h("label", {}, "Lock after this many idle minutes ", idle),
    h("button", { id: "save-settings", on: { click: () => void act(settingsStatus, async () => {
      await send({ type: "setSettings", settings: { idleMinutes: Number(idle.value) } });
      return "Saved.";
    }) } }, "Save"), settingsStatus);

  replace(app, h("h1", {}, "vault"), promptArea, resolve, passwd, restore, server, offers, prefs);
  const target = location.hash.slice(1);
  if (target) document.getElementById(target)?.scrollIntoView();
}

/** Runs an action, showing its result or error under it, then redraws the page. */
async function act(el: HTMLElement, fn: () => Promise<string>): Promise<void> {
  message(el, "Working…", "info");
  try {
    const text = await fn();
    await main();
    const again = document.getElementById(el.parentElement?.id ?? "");
    message((again?.lastElementChild as HTMLElement | null) ?? el, text, "info");
  } catch (e) {
    message(el, errorText(e));
  }
}

async function interactive(state: State, config: Config, unlocked: boolean): Promise<string> {
  const keys = await keysFor(state);
  try {
    const proc = unlocked ? Procedure.sync(state, keys, "interactive-ask-again") : Procedure.unlock(state, keys);
    const done = await run(proc, state, config, unlocked);
    if (!done.ok) return done.error.message;
    await send({ type: "syncNow" }).catch(() => {});
    return "Done.";
  } finally {
    zero(keys);
  }
}

async function recover(state: State, config: Config): Promise<string> {
  const keys = await keysFor(state);
  try {
    const done = await run(Procedure.recover(state, keys), state, config, keys.vaultKey !== undefined);
    return done.ok ? "Recovery finished." : done.error.message;
  } finally {
    zero(keys);
  }
}

async function repairToken(state: State, config: Config, text: string): Promise<string> {
  const parsed = parseSetupText(text);
  if (permissionFor(parsed.url) !== config.permission || parsed.url !== config.url) {
    throw new Error("The setup text is for a different server. Set up again instead.");
  }
  const server = { url: parsed.url, token: parsed.token };
  const done = await run(Procedure.repairToken(state), state, server, await unlockedNow(),
    (host) => host.writeConfig({ ...config, token: parsed.token, fp: parsed.fp }));
  return done.ok ? "The token is replaced." : done.error.message;
}

async function listRevisions(area: HTMLElement, config: Config): Promise<void> {
  const r = await sendRequest(config, { type: "request", method: "GET", path: "/v1/revisions" });
  if (r.type !== "response" || r.status !== 200) return message(area, "The server's revisions cannot be read.");
  const revisions = parseRevisions(r.body);
  replace(area, h("ul", { class: "items", id: "revisions" }, ...revisions.map((rev) => h("li", {},
    h("span", { class: "name" }, `${rev.created} by ${rev.token} (${rev.size} bytes)`),
    h("button", { class: "restore-revision", on: { click: () => void restoreRevision(area, config, rev.id) } }, "Restore")))));
}

async function restoreRevision(area: HTMLElement, config: Config, id: number): Promise<void> {
  const state = await store.readState();
  if (state === null) return;
  const keys = await keysFor(state);
  try {
    if (keys.vaultKey === undefined) return message(area, "Unlock the vault first.");
    const epoch = lockEpoch;
    const proc = Procedure.fetchRevision(state, keys, id);
    const releaseProc = hold(proc);
    const done = await drive(proc, config, { prompt: ask }).catch((e) => {
      releaseProc();
      throw e;
    });
    if (!done.ok || lockEpoch !== epoch) {
      releaseProc();
      return message(area, done.ok ? "The vault locked; unlock and start the restore again." : done.error.message);
    }
    // The page's own session, held until the restore is confirmed or abandoned, and closed at once
    // when the vault locks anywhere.
    const session = Session.reopen(state, keys.vaultKey);
    const releaseSession = hold(session);
    const release = () => {
      releaseSession();
      releaseProc();
    };
    addEventListener("pagehide", release, { once: true });
    let p: { added: number; changed: number; removed: number };
    try {
      p = session.restorePreview(proc);
    } catch (e) {
      release();
      throw e;
    }
    replace(area, h("p", {}, `Restoring revision ${id} adds ${p.added}, changes ${p.changed}, and removes ${p.removed} items. The restore is a new change; history is kept.`),
      h("button", { id: "restore-confirm", on: { click: () => void act(area, async () => {
        try {
          if (lockEpoch !== epoch || !(await unlockedNow())) {
            throw new Error("The vault is locked; unlock and start the restore again.");
          }
          await store.commit((onDisk, host) => {
            if (onDisk === null) throw new Error("no state");
            host.writeState(session.restore(onDisk, config.deviceId, Date.now(), proc).state);
          });
        } finally {
          release();
        }
        await send({ type: "stateChanged" });
        await send({ type: "syncNow" }).catch(() => {});
        return "Restored.";
      }) } }, "Restore"));
  } finally {
    zero(keys);
  }
}

async function main(): Promise<void> {
  await loadWasm();
  const [state, config] = await Promise.all([store.readState(), store.readConfig()]);
  if (state === null || config === null) return renderSetup();
  return renderVault(state, config);
}

void main().catch((e) => replace(app, h("p", { class: "flash error" }, errorText(e))));
