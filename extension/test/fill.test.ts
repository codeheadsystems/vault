import assert from "node:assert/strict";
import { test } from "node:test";
import * as esbuild from "esbuild";
import { Window } from "happy-dom";
import { fillFrame, type FillResult } from "../src/fill/fill.ts";

type Fill = typeof fillFrame;

/**
 * A document at `url` with `html`, exposed as the globals the fill script uses. happy-dom has no
 * layout, so this one supplies a little: an element's box comes from its data-rect attribute
 * ("left,top,width,height"); inputs without one stack down the page, 30 px apart; other elements
 * span the page. elementFromPoint returns the last input or data-cover element whose box holds the
 * point. The window gets an origin, which happy-dom lacks.
 */
function page(url: string, html: string, origin = new URL(url).origin) {
  const window = new Window({ url, width: 1024, height: 768 });
  Object.defineProperty(window, "origin", { value: origin });
  const doc = window.document;
  const boxOf = (el: Element): number[] => {
    const r = el.getAttribute("data-rect");
    if (r !== null) {
      const [x, y, w, h] = r.split(",").map(Number);
      return [x, y, w, h];
    }
    if (el.tagName === "INPUT") return [10, 10 + Array.from(doc.querySelectorAll("input")).indexOf(el as never) * 30, 200, 20];
    return [0, 0, 1024, 3000];
  };
  const proto = window.Element.prototype as unknown as { getBoundingClientRect(): DOMRect };
  proto.getBoundingClientRect = function (this: Element) {
    const [x, y, w, h] = boxOf(this);
    return { x, y, width: w, height: h, left: x, top: y, right: x + w, bottom: y + h } as DOMRect;
  };
  (doc as unknown as { elementFromPoint(x: number, y: number): unknown }).elementFromPoint = (x: number, y: number): unknown => {
    let hit: unknown = doc.body;
    for (const el of doc.querySelectorAll("input, [data-cover], label")) {
      const [l, t, w, h] = boxOf(el as unknown as Element);
      if (x >= l && x < l + w && y >= t && y < t + h) hit = el;
    }
    return hit;
  };
  doc.body.innerHTML = html;
  // The document is 1024 by 3000 px.
  Object.defineProperty(doc.documentElement, "scrollWidth", { value: 1024 });
  Object.defineProperty(doc.documentElement, "scrollHeight", { value: 3000 });
  const g = globalThis as Record<string, unknown>;
  for (const k of ["document", "HTMLInputElement", "Event", "Node", "getComputedStyle", "innerWidth", "innerHeight", "scrollX", "scrollY"]) {
    g[k] = (window as unknown as Record<string, unknown>)[k];
  }
  g.self = window;
  const events: string[] = [];
  for (const el of doc.querySelectorAll("input")) {
    for (const t of ["input", "change"]) el.addEventListener(t, () => events.push(`${el.id}:${t}`));
  }
  const value = (id: string) => (doc.getElementById(id) as unknown as HTMLInputElement).value;
  return { window, value, events };
}

const LOGIN = `<form><input id="u" type="email"><input id="p" type="password"><button>Sign in</button></form>`;

test("fills the username and password of a login form and dispatches input and change", () => {
  const { value, events } = page("https://example.com/login", LOGIN);
  const r = fillFrame("https://example.com", "ann@example.com", "s3cret", "login");
  assert.deepEqual(r, { origin: true, usernameFilled: true, passwordsFilled: 1 });
  assert.equal(value("u"), "ann@example.com");
  assert.equal(value("p"), "s3cret");
  assert.deepEqual(events, ["u:input", "u:change", "p:input", "p:change"]);
});

test("writes nothing when self.origin differs from the expected origin", () => {
  const { value, events } = page("https://login.example.com/", LOGIN);
  const r = fillFrame("https://www.example.com", "ann", "s3cret", "login");
  assert.deepEqual(r, { origin: false, usernameFilled: false, passwordsFilled: 0 });
  assert.equal(value("u"), "");
  assert.equal(value("p"), "");
  assert.deepEqual(events, []);
});

test("checks self.origin, not location.origin: an about:blank frame inheriting the origin fills", () => {
  const { value } = page("about:blank", LOGIN, "https://example.com");
  assert.equal(fillFrame("https://example.com", "ann", "pw", "login").passwordsFilled, 1);
  assert.equal(value("p"), "pw");
});

test("skips hidden, disabled, and read-only fields", () => {
  const { value } = page("https://example.com/", `
    <form>
      <input id="trap-user" type="text" style="display:none">
      <input id="trap-pass" type="password" style="visibility:hidden">
      <input id="ro" type="text" readonly>
      <input id="u" type="text">
      <input id="dis" type="password" disabled>
      <input id="p" type="password">
    </form>`);
  fillFrame("https://example.com", "ann", "pw", "login");
  assert.equal(value("u"), "ann");
  assert.equal(value("p"), "pw");
  for (const id of ["trap-user", "trap-pass", "ro", "dis"]) assert.equal(value(id), "", id);
});

test("takes the username field from the password field's form", () => {
  const { value } = page("https://example.com/", `
    <form><input id="search" type="text"></form>
    <form><input id="u" type="text"><input id="p" type="password"></form>`);
  fillFrame("https://example.com", "ann", "pw", "login");
  assert.equal(value("search"), "");
  assert.equal(value("u"), "ann");
});

test("prefers the current password over a new-password field", () => {
  const { value } = page("https://example.com/", `
    <form><input id="u"><input id="cur" type="password" autocomplete="current-password">
    <input id="new" type="password" autocomplete="new-password"></form>`);
  fillFrame("https://example.com", "ann", "pw", "login");
  assert.equal(value("cur"), "pw");
  assert.equal(value("new"), "");
});

test("a username-first page gets only the username", () => {
  const { value } = page("https://example.com/", `<form><input id="u" autocomplete="username"><button>Next</button></form>`);
  assert.deepEqual(fillFrame("https://example.com", "ann", "pw", "login"), { origin: true, usernameFilled: true, passwordsFilled: 0 });
  assert.equal(value("u"), "ann");
});

test("generate fills the new password and its empty confirmation field, not the current password", () => {
  const { value } = page("https://example.com/", `
    <form><input id="cur" type="password" autocomplete="current-password" value="old">
    <input id="new" type="password" autocomplete="new-password"><input id="again" type="password"></form>`);
  const r = fillFrame("https://example.com", "", "G3n!", "generate");
  assert.equal(r.passwordsFilled, 2);
  assert.equal(value("cur"), "old");
  assert.equal(value("new"), "G3n!");
  assert.equal(value("again"), "G3n!");
});

test("generate with no visible password field fills nothing", () => {
  page("https://example.com/", `<form><input id="u"><input id="p" type="password" style="display:none"></form>`);
  assert.equal(fillFrame("https://example.com", "", "x", "generate").passwordsFilled, 0);
});

/** Fills a page with a decoy password field (and username) before the real form, and returns
 * the values each received. */
function decoy(decoyHtml: string) {
  const { value } = page("https://example.com/", `
    <form>${decoyHtml}</form>
    <form><input id="u" type="text"><input id="p" type="password"></form>`);
  fillFrame("https://example.com", "ann", "pw", "login");
  return { decoy: value("dp"), real: value("p"), user: value("u") };
}

for (const [name, html] of [
  ["off the page", `<input id="dp" type="password" data-rect="-500,-500,200,20">`],
  ["below the document", `<input id="dp" type="password" data-rect="10,5000,200,20">`],
  ["1 px", `<input id="dp" type="password" data-rect="10,10,1,1">`],
  ["3 by 3 px", `<input id="dp" type="password" data-rect="10,10,3,3">`],
  ["opacity 0.01 on an ancestor", `<div style="opacity: 0.01"><input id="dp" type="password"></div>`],
  ["opacity 0.05 on the field", `<input id="dp" type="password" style="opacity: 0.05">`],
  ["clipped by an ancestor's overflow", `<div style="overflow: hidden" data-rect="0,0,2,2"><input id="dp" type="password"></div>`],
  ["clipped by clip", `<input id="dp" type="password" style="position: absolute; clip: rect(0px, 1px, 1px, 0px)">`],
  ["clipped by clip-path", `<input id="dp" type="password" style="clip-path: inset(50%)">`],
  ["covered by another element", `<input id="dp" type="password" data-rect="10,500,200,20"><div data-cover data-rect="0,490,400,60"></div>`],
] as const) {
  test(`a decoy password field ${name} gets nothing; the real form is filled`, () => {
    const r = decoy(html);
    assert.equal(r.decoy, "", "decoy");
    assert.equal(r.real, "pw");
    assert.equal(r.user, "ann");
  });
}

test("a field whose label covers its centre counts as visible", () => {
  const { value } = page("https://example.com/", `
    <form><input id="u"><label for="p" data-rect="0,40,400,40">Password</label><input id="p" type="password" data-rect="10,45,200,20"></form>`);
  fillFrame("https://example.com", "ann", "pw", "login");
  assert.equal(value("p"), "pw");
});

test("a field outside the viewport but on the page is filled", () => {
  const { value } = page("https://example.com/", `<form><input id="u" data-rect="10,1500,200,20"><input id="p" type="password" data-rect="10,1530,200,20"></form>`);
  fillFrame("https://example.com", "ann", "pw", "login");
  assert.equal(value("p"), "pw");
  assert.equal(value("u"), "ann");
});

test("the bundled fill function refers to nothing outside its own body", async () => {
  // scripting.executeScript serialises the function, so esbuild must not have added helpers it
  // calls. Build the background bundle as `npm run build` does and run the function's text alone.
  const out = await esbuild.build({
    stdin: { contents: `import { fillFrame } from "./src/fill/fill.ts"; globalThis.f = fillFrame;`, resolveDir: process.cwd(), loader: "ts" },
    bundle: true, write: false, format: "iife", target: "firefox153", minify: false,
  });
  const text = out.outputFiles[0].text;
  const start = text.indexOf("function fillFrame(");
  assert.ok(start >= 0);
  let depth = 0;
  let end = text.indexOf("{", start);
  for (let i = end; i < text.length; i++) {
    if (text[i] === "{") depth++;
    if (text[i] === "}" && --depth === 0) {
      end = i + 1;
      break;
    }
  }
  const standalone = new Function(`return (${text.slice(start, end)})`)() as Fill;
  const { value } = page("https://example.com/", LOGIN);
  const r: FillResult = standalone("https://example.com", "ann", "pw", "login");
  assert.equal(r.passwordsFilled, 1);
  assert.equal(value("p"), "pw");
});
