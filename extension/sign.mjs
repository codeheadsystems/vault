// Signs the packed extension as an unlisted add-on through the addons.mozilla.org v5 API
// (docs/firefox.md, Distribution): upload the .xpi, wait for validation, create the add-on or a new
// version of it, wait for the signed file, and download it to artifacts/.
//
// AMO_API_KEY and AMO_API_SECRET hold the API credentials (the JWT issuer and secret from AMO's
// "Manage API Keys" page); they are read from the environment only, and the JWT goes only to the
// API's own origin. AMO_BASE_URL overrides the API host. The source archive from `npm run source`
// is attached to the version for reviewers, because the extension ships compiled WebAssembly. A
// stub build, an end-to-end timing build, or a dirty working tree is refused.

import { createHash, createHmac, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pack } from "./pack.mjs";
import { buildSource } from "./source.mjs";

const b64url = (b) => Buffer.from(b).toString("base64url");

/**
 * An HS256 JWT for the AMO API: issuer the API key, a random jti, and a lifetime of 60 seconds
 * (AMO accepts at most 5 minutes).
 */
export function jwt(key, secret, nowSeconds = Math.floor(Date.now() / 1000), jti = randomBytes(16).toString("hex")) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iss: key, jti, iat: nowSeconds, exp: nowSeconds + 60 }));
  const signature = createHmac("sha256", secret).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${signature}`;
}

export class SignError extends Error {}

/**
 * Uploads `xpi` and returns the signed file's bytes.
 * @param {{ xpi: string; guid: string; key: string; secret: string; base?: string; source?: string | null;
 *   fetch?: typeof fetch; sleep?: (ms: number) => Promise<void>; log?: (s: string) => void;
 *   pollMs?: number; timeoutMs?: number }} o
 */
export async function signXpi(o) {
  const base = (o.base ?? "https://addons.mozilla.org").replace(/\/+$/, "");
  const doFetch = o.fetch ?? fetch;
  const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const log = o.log ?? ((s) => console.log(s));
  const pollMs = o.pollMs ?? 5_000;
  const deadline = Date.now() + (o.timeoutMs ?? 20 * 60_000);
  const guid = encodeURIComponent(o.guid);

  const origin = new URL(base).origin;
  const call = async (method, path, body, accept = [200, 201]) => {
    const url = path.startsWith("http") ? path : `${base}${path}`;
    // The credentials go to AMO's API origin only, never to a download host elsewhere.
    const headers = new URL(url).origin === origin ? { Authorization: `JWT ${jwt(o.key, o.secret)}` } : {};
    if (body !== undefined && !(body instanceof FormData)) headers["Content-Type"] = "application/json";
    const r = await doFetch(url, {
      method, headers, body: body === undefined || body instanceof FormData ? body : JSON.stringify(body),
    });
    if (!accept.includes(r.status)) {
      const text = await r.text().catch(() => "");
      throw new SignError(`${method} ${path}: HTTP ${r.status} ${text.slice(0, 500)}`);
    }
    return r;
  };
  const poll = async (what, fn) => {
    for (;;) {
      const v = await fn();
      if (v) return v;
      if (Date.now() > deadline) throw new SignError(`timed out waiting for ${what}`);
      await sleep(pollMs);
    }
  };

  const form = new FormData();
  form.append("upload", new Blob([readFileSync(o.xpi)], { type: "application/x-xpinstall" }), basename(o.xpi));
  form.append("channel", "unlisted");
  const upload = await (await call("POST", "/api/v5/addons/upload/", form)).json();
  log(`sign: uploaded, ${upload.uuid}`);
  const checked = await poll("validation", async () => {
    const u = await (await call("GET", `/api/v5/addons/upload/${upload.uuid}/`)).json();
    return u.processed ? u : null;
  });
  if (!checked.valid) {
    const messages = (checked.validation?.messages ?? []).map((m) => `${m.type}: ${m.message}`).join("\n  ");
    throw new SignError(`validation failed:\n  ${messages}`);
  }

  const existing = await call("GET", `/api/v5/addons/addon/${guid}/`, undefined, [200, 401, 403, 404]);
  let version;
  if (existing.status === 200) {
    version = await (await call("POST", `/api/v5/addons/addon/${guid}/versions/`, { upload: upload.uuid })).json();
  } else {
    const addon = await (await call("POST", "/api/v5/addons/addon/", { version: { upload: upload.uuid } })).json();
    version = addon.latest_unlisted_version ?? addon.version;
  }
  if (!version?.id) throw new SignError("AMO returned no version");
  log(`sign: version ${version.version ?? ""} (${version.id}) created`);
  if (o.source) {
    const s = new FormData();
    s.append("source", new Blob([readFileSync(o.source)], { type: "application/zip" }), basename(o.source));
    await call("PATCH", `/api/v5/addons/addon/${guid}/versions/${version.id}/`, s);
    log(`sign: attached ${basename(o.source)}`);
  }
  const file = await poll("the signed file", async () => {
    const v = await (await call("GET", `/api/v5/addons/addon/${guid}/versions/${version.id}/`)).json();
    if (v.file?.status === "disabled") throw new SignError("AMO disabled the file");
    return v.file?.status === "public" && v.file.url ? v.file : null;
  });
  const signed = new Uint8Array(await (await call("GET", file.url)).arrayBuffer());
  // AMO gives the file's hash as "sha256:<hex>"; a download that differs is refused.
  const m = /^sha256:([0-9a-f]{64})$/.exec(file.hash ?? "");
  if (m !== null && createHash("sha256").update(signed).digest("hex") !== m[1]) {
    throw new SignError("the signed file does not match the hash AMO reported");
  }
  return signed;
}

async function main() {
  const root = fileURLToPath(new URL(".", import.meta.url));
  const problems = [];
  if (existsSync(join(root, "dist", "STUB"))) problems.push("dist/ uses the vault-wasm stub");
  if (existsSync(join(root, "dist", "E2E_TIMING"))) problems.push("dist/ has the end-to-end test timings");
  const manifest = JSON.parse(readFileSync(join(root, "dist", "manifest.json"), "utf8"));
  const guid = manifest.browser_specific_settings?.gecko?.id ?? "";
  if (guid === "" || guid.endsWith(".invalid")) problems.push(`the gecko ID "${guid}" is a placeholder`);
  const key = process.env.AMO_API_KEY;
  const secret = process.env.AMO_API_SECRET;
  if (!key || !secret) problems.push("set AMO_API_KEY and AMO_API_SECRET in the environment");
  if (problems.length > 0) {
    console.error(`sign: refusing to sign:\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  const source = buildSource(root);
  const xpi = pack(root);
  const signed = await signXpi({ xpi, guid, key, secret, base: process.env.AMO_BASE_URL, source });
  const out = join(root, "artifacts", `vault-${manifest.version}-signed.xpi`);
  writeFileSync(out, signed);
  console.log(`sign: ${out}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`sign: ${e.message}`);
    process.exit(1);
  });
}
