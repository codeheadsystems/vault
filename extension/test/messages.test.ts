import assert from "node:assert/strict";
import { test } from "node:test";
import { isExtensionPage, isTopFrameContentScript, parseRequest, parseSaveSubmit } from "../src/shared/messages.ts";

const ID = "vault@codeheadsystems.com";
const ORIGIN = "moz-extension://1234-5678";
const BASE = `${ORIGIN}/`;
const ITEM = "0f8fad5b-d9cb-469f-a165-70867728950e";

test("well-formed requests parse", () => {
  for (const r of [
    { type: "status" },
    { type: "unlock", password: "correct horse" },
    { type: "list", text: "" },
    { type: "copy", id: ITEM, field: "password" },
    { type: "fill", id: ITEM, confirmedHost: null },
    { type: "fill", id: ITEM, confirmedHost: "nas.lan:8443" },
    { type: "add", item: { type: "login", name: "x", uris: [{ uri: "https://x.example", match: "base_domain" }] } },
    { type: "update", id: ITEM, base: { name: "a" }, edited: { name: "b" } },
    { type: "generate", options: { kind: "passphrase", words: 6, separator: "-" } },
    { type: "offerSave", origin: "https://example.com" },
    { type: "setSettings", settings: { idleMinutes: 15 } },
  ]) {
    assert.deepEqual(parseRequest(r), r, JSON.stringify(r));
  }
});

test("malformed requests are refused", () => {
  for (const r of [
    null, "status", [], { type: "nope" }, { type: "toString" }, { type: "__proto__" },
    { type: "status", extra: 1 },
    { type: "unlock" },
    { type: "unlock", password: 5 },
    { type: "unlock", password: "x".repeat(5000) },
    { type: "copy", id: ITEM, field: "notes" },
    { type: "copy", id: "../etc", field: "password" },
    { type: "fill", id: ITEM },
    { type: "add", item: { type: "login", name: "  " } },
    { type: "add", item: { type: "card", name: "x" } },
    { type: "add", item: { type: "login", name: "x", uris: [{ uri: "u", match: "regex" }] } },
    { type: "update", id: ITEM, base: [], edited: {} },
    { type: "generate", options: { kind: "password", length: 2, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false } },
    { type: "offerSave", origin: "https://example.com/path" },
    { type: "setSettings", settings: { idleMinutes: 0 } },
    Object.assign(Object.create({ inherited: true }), { type: "status" }),
    // Keys a shape object inherits from Object.prototype are not part of the shape.
    { type: "status", toString: "x" },
    { type: "status", constructor: {} },
    { type: "unlock", password: "x", hasOwnProperty: 1 },
  ]) {
    assert.equal(parseRequest(r), null, JSON.stringify(r));
  }
});

test("the save watcher's message has exactly its shape", () => {
  assert.ok(parseSaveSubmit({ type: "saveSubmit", username: "u", password: "p" }));
  assert.equal(parseSaveSubmit({ type: "saveSubmit", username: "u", password: "" }), null);
  assert.equal(parseSaveSubmit({ type: "saveSubmit", username: "u", password: "p", url: "https://evil" }), null);
  assert.equal(parseSaveSubmit({ type: "status" }), null);
});

test("extension pages: the popup and the vault page, and nothing else", () => {
  assert.ok(isExtensionPage({ id: ID, url: `${ORIGIN}/popup.html`, envType: "addon_child" }, ID, BASE));
  assert.ok(isExtensionPage({ id: ID, url: `${ORIGIN}/page.html`, tab: { id: 3, url: `${ORIGIN}/page.html#setup` } }, ID, BASE));
  // Another extension, a content script, a web page, or a mismatched tab.
  assert.ok(!isExtensionPage({ id: "other@x", url: `${ORIGIN}/popup.html` }, ID, BASE));
  assert.ok(!isExtensionPage({ id: ID, url: "https://example.com/", tab: { id: 3, url: "https://example.com/" } }, ID, BASE));
  assert.ok(!isExtensionPage({ id: ID, url: `${ORIGIN}/page.html`, tab: { id: 3, url: "https://example.com/" } }, ID, BASE));
  assert.ok(!isExtensionPage({ id: ID, url: `${ORIGIN}/popup.html`, envType: "content_child" }, ID, BASE));
  assert.ok(!isExtensionPage({ id: ID, url: "moz-extension://other-uuid/popup.html" }, ID, BASE));
  assert.ok(!isExtensionPage({ id: ID }, ID, BASE));
  assert.ok(!isExtensionPage({ id: ID, url: "moz-extension://1234-5678.evil/popup.html" }, ID, BASE));
});

test("content scripts: only the top frame of a web page", () => {
  const tab = { id: 7, url: "https://example.com/login" };
  assert.ok(isTopFrameContentScript({ id: ID, tab, frameId: 0, url: "https://example.com/login", envType: "content_child" }, ID));
  assert.ok(!isTopFrameContentScript({ id: ID, tab, frameId: 12, url: "https://ads.example/x" }, ID));
  assert.ok(!isTopFrameContentScript({ id: ID, frameId: 0, url: "https://example.com/" }, ID));
  assert.ok(!isTopFrameContentScript({ id: "other@x", tab, frameId: 0, url: "https://example.com/" }, ID));
  assert.ok(!isTopFrameContentScript({ id: ID, tab, frameId: 0, url: `${ORIGIN}/page.html` }, ID));
});
