import assert from "node:assert/strict";
import { test } from "node:test";
import { apiUrl, probe, send } from "../src/shared/transport.ts";

const server = { url: "https://nas.lan:8443/vault/", token: "TOKEN" };

test("requests carry the token and preconditions, refuse redirects, omit credentials, and bypass the cache", async () => {
  let seen: { url: string; init: RequestInit } | null = null;
  const fake = (async (url: string, init: RequestInit) => {
    seen = { url, init };
    return new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { Date: "Mon, 12 Oct 2026 23:57:41 GMT" } });
  }) as unknown as typeof fetch;
  const body = new Uint8Array([9]);
  const r = await send(server, { type: "request", method: "PUT", path: "/v1/vault", ifMatch: '"abc"', body }, fake);
  assert.equal(seen!.url, "https://nas.lan:8443/vault/v1/vault");
  assert.equal(seen!.init.redirect, "error");
  assert.equal(seen!.init.credentials, "omit");
  assert.equal(seen!.init.cache, "no-store");
  assert.deepEqual(seen!.init.headers, { Authorization: "Bearer TOKEN", "If-Match": '"abc"', "Content-Type": "application/octet-stream" });
  assert.deepEqual(r, { type: "response", status: 200, body: new Uint8Array([1, 2, 3]), date: Date.UTC(2026, 9, 12, 23, 57, 41) });
});

test("a missing or unreadable Date is left out, and a transport error is unreachable", async () => {
  const noDate = (async () => new Response(null, { status: 404 })) as unknown as typeof fetch;
  assert.deepEqual(await send(server, { type: "request", method: "GET", path: "/v1/vault" }, noDate), { type: "response", status: 404, body: new Uint8Array() });
  const broken = (async () => {
    throw new TypeError("NetworkError when attempting to fetch resource.");
  }) as unknown as typeof fetch;
  assert.deepEqual(await send(server, { type: "request", method: "GET", path: "/v1/vault" }, broken), { type: "unreachable" });
});

test("API paths keep the server URL's path prefix", () => {
  assert.equal(apiUrl("http://localhost:8080", "/v1/vault"), "http://localhost:8080/v1/vault");
  assert.equal(apiUrl("http://localhost:8080/", "/v1/vault"), "http://localhost:8080/v1/vault");
  assert.equal(apiUrl("https://h.example/vault//", "/v1/revisions/3"), "https://h.example/vault/v1/revisions/3");
});

test("the setup probe sends no token, and any response, even a 401, proves TLS", async () => {
  let headers: unknown = "unset";
  const fake = (async (_url: string, init: RequestInit) => {
    headers = init.headers;
    return new Response(null, { status: 401 });
  }) as unknown as typeof fetch;
  assert.equal(await probe("https://nas.lan:8443/", fake), true);
  assert.equal(headers, undefined, "no Authorization");
  const broken = (async () => {
    throw new TypeError("certificate not trusted");
  }) as unknown as typeof fetch;
  assert.equal(await probe("https://nas.lan:8443/", broken), false);
});
