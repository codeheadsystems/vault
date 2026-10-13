// The sender checks against the sender objects Firefox 157 really gives (recorded by
// e2e/security.test.ts with E2E_RECORD_SENDERS=1), and against variations of them.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { isExtensionPage, isTopFrameContentScript, type Sender } from "../src/shared/messages.ts";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/senders.json", import.meta.url), "utf8")) as {
  id: string;
  base: string;
  senders: Record<"popup" | "vault page" | "content script", Sender & { tab: { url: string }; origin: string }>;
};
const { id, base, senders } = fixture;
const popup = senders.popup;
const page = senders["vault page"];
const content = senders["content script"];

test("the recorded senders have the shape the checks rely on", () => {
  assert.equal(popup.envType, "addon_child");
  assert.equal(page.envType, "addon_child");
  assert.equal(content.envType, "content_child");
  assert.equal(content.frameId, 0);
  assert.ok(content.tab.url.startsWith("http"));
});

test("the popup and the vault page are extension pages; the content script is not", () => {
  assert.ok(isExtensionPage(page, id, base), "the vault page, in a tab");
  assert.ok(isExtensionPage(popup, id, base), "the popup, in a popup window, as the end-to-end tests open it");
  const { tab: _tab, ...panel } = popup;
  assert.ok(isExtensionPage(panel, id, base), "the popup as the toolbar panel, with no tab");
  assert.ok(!isExtensionPage(content, id, base));
});

test("the content script is a top-frame content script; nothing else is", () => {
  assert.ok(isTopFrameContentScript(content, id));
  assert.ok(!isTopFrameContentScript({ ...content, frameId: 7, url: "http://ads.example/frame.html" }, id), "a subframe");
  assert.ok(!isTopFrameContentScript(page, id));
  assert.ok(!isTopFrameContentScript(popup, id));
});

test("variations that must fail", () => {
  assert.ok(!isExtensionPage({ ...page, id: "other@example.com" }, id, base), "another extension");
  assert.ok(!isExtensionPage({ ...page, envType: "content_child" }, id, base), "a content script's envType");
  assert.ok(!isExtensionPage({ ...page, tab: { ...page.tab, url: content.tab.url } }, id, base), "an extension URL in a web page's tab");
  assert.ok(!isExtensionPage({ ...content, url: `${base}popup.html` }, id, base), "an extension URL from a content script");
  assert.ok(!isTopFrameContentScript({ ...content, id: "other@example.com" }, id));
  assert.ok(!isTopFrameContentScript({ ...content, tab: undefined }, id));
});
