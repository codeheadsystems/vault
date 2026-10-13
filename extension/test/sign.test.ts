import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { jwt, SignError, signXpi } from "../sign.mjs";

const KEY = "user:12345:67";
const SECRET = "s3cr3t";
const GUID = "vault@codeheadsystems.com";
const BASE = "https://amo.test";

test("the JWT is HS256 over the issuer, a jti, and a 60-second lifetime", () => {
  const t = jwt(KEY, SECRET, 1_800_000_000, "abc");
  const [h, p, s] = t.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(h, "base64url").toString()), { alg: "HS256", typ: "JWT" });
  assert.deepEqual(JSON.parse(Buffer.from(p, "base64url").toString()), { iss: KEY, jti: "abc", iat: 1_800_000_000, exp: 1_800_000_060 });
  assert.equal(s, createHmac("sha256", SECRET).update(`${h}.${p}`).digest("base64url"));
  assert.notEqual(jwt(KEY, SECRET).split(".")[1], jwt(KEY, SECRET).split(".")[1], "a fresh jti each time");
});

/** A fake AMO: checks every request's JWT and records the calls. */
function fakeAmo(opts: { exists: boolean; valid?: boolean; cdn?: boolean; hash?: string }) {
  const calls: string[] = [];
  let polls = 0;
  const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
  const fetchImpl = async (url: string, init: RequestInit) => {
    const auth = (init.headers as Record<string, string>).Authorization;
    if (!url.startsWith(BASE)) {
      // A download from another host gets no credentials.
      assert.equal(auth, undefined, `credentials sent to ${url}`);
      calls.push(`${init.method} ${url}`);
      return new Response(new Uint8Array([0x50, 0x4b, 1, 2]));
    }
    const [h, p, s] = auth.replace(/^JWT /, "").split(".");
    assert.equal(s, createHmac("sha256", SECRET).update(`${h}.${p}`).digest("base64url"), "JWT signature");
    assert.equal(JSON.parse(Buffer.from(p, "base64url").toString()).iss, KEY);
    const path = url.replace(BASE, "");
    calls.push(`${init.method} ${path}`);
    const g = encodeURIComponent(GUID);
    if (init.method === "POST" && path === "/api/v5/addons/upload/") {
      const form = init.body as FormData;
      assert.equal(form.get("channel"), "unlisted");
      assert.ok(form.get("upload") instanceof Blob);
      return json({ uuid: "u1", processed: false });
    }
    if (path === "/api/v5/addons/upload/u1/") return json(++polls < 2 ? { uuid: "u1", processed: false } : { uuid: "u1", processed: true, valid: opts.valid ?? true, validation: { messages: [{ type: "error", message: "bad manifest" }] } });
    if (init.method === "GET" && path === `/api/v5/addons/addon/${g}/`) return opts.exists ? json({ guid: GUID }) : json({ detail: "Not found." }, 404);
    if (init.method === "POST" && path === `/api/v5/addons/addon/${g}/versions/`) return json({ id: 9, version: "0.1.0" }, 201);
    if (init.method === "POST" && path === "/api/v5/addons/addon/") {
      assert.deepEqual(JSON.parse(init.body as string), { version: { upload: "u1" } });
      return json({ guid: GUID, latest_unlisted_version: { id: 9, version: "0.1.0" } }, 201);
    }
    if (path === `/api/v5/addons/addon/${g}/versions/9/`) {
      const url = opts.cdn ? "https://cdn.amo.test/files/signed.xpi" : `${BASE}/files/signed.xpi`;
      return json({ id: 9, file: polls++ < 4 ? { status: "unreviewed" } : { status: "public", url, hash: opts.hash } });
    }
    if (path === "/files/signed.xpi") return new Response(new Uint8Array([0x50, 0x4b, 1, 2]));
    return json({ detail: "unexpected" }, 500);
  };
  return { calls, fetchImpl: fetchImpl as unknown as typeof fetch };
}

function xpi(): string {
  const p = join(mkdtempSync(join(tmpdir(), "vault-sign-")), "vault.xpi");
  writeFileSync(p, Buffer.from("PK fake"));
  return p;
}

for (const exists of [false, true]) {
  test(`signs ${exists ? "a new version of an existing" : "a new"} unlisted add-on`, async () => {
    const amo = fakeAmo({ exists });
    const signed = await signXpi({ xpi: xpi(), guid: GUID, key: KEY, secret: SECRET, base: BASE, fetch: amo.fetchImpl, sleep: async () => {}, log: () => {} });
    assert.deepEqual(signed, new Uint8Array([0x50, 0x4b, 1, 2]));
    const g = encodeURIComponent(GUID);
    assert.deepEqual(amo.calls.filter((c) => !c.includes("/upload/u1/") && !c.includes("/versions/9/")), [
      "POST /api/v5/addons/upload/",
      `GET /api/v5/addons/addon/${g}/`,
      exists ? `POST /api/v5/addons/addon/${g}/versions/` : "POST /api/v5/addons/addon/",
      "GET /files/signed.xpi",
    ]);
  });
}

test("a failed validation stops with its messages", async () => {
  const amo = fakeAmo({ exists: true, valid: false });
  await assert.rejects(
    signXpi({ xpi: xpi(), guid: GUID, key: KEY, secret: SECRET, base: BASE, fetch: amo.fetchImpl, sleep: async () => {}, log: () => {} }),
    (e: unknown) => e instanceof SignError && /bad manifest/.test(e.message),
  );
});

const SIGNED_HASH = "sha256:" + createHash("sha256").update(new Uint8Array([0x50, 0x4b, 1, 2])).digest("hex");

test("the JWT goes only to AMO's API origin, and the download is checked against AMO's hash", async () => {
  const amo = fakeAmo({ exists: true, cdn: true, hash: SIGNED_HASH });
  const signed = await signXpi({ xpi: xpi(), guid: GUID, key: KEY, secret: SECRET, base: BASE, fetch: amo.fetchImpl, sleep: async () => {}, log: () => {} });
  assert.equal(signed.length, 4);
  assert.ok(amo.calls.includes("GET https://cdn.amo.test/files/signed.xpi"));
});

test("a download that does not match AMO's hash is refused", async () => {
  const amo = fakeAmo({ exists: true, hash: "sha256:" + "0".repeat(64) });
  await assert.rejects(
    signXpi({ xpi: xpi(), guid: GUID, key: KEY, secret: SECRET, base: BASE, fetch: amo.fetchImpl, sleep: async () => {}, log: () => {} }),
    /does not match the hash/,
  );
});
