// The extension's own lint (docs/firefox.md, Build and tests): the manifest grants exactly what the
// design needs, the pages load only packaged scripts, and no bundle evaluates code from strings.

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import * as esbuild from "esbuild";
import { currentGlue, esbuildOptions, root } from "../build-config.mjs";

const manifest = JSON.parse(readFileSync(join(root, "static", "manifest.json"), "utf8"));

test("the gecko ID, the minimum Firefox version, and no data collection", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.browser_specific_settings, {
    gecko: { id: "vault@codeheadsystems.com", strict_min_version: "153.0", data_collection_permissions: { required: ["none"] } },
  });
});

test("exactly the expected permissions; site access only as optional host permissions", () => {
  assert.deepEqual([...manifest.permissions].sort(), [
    "activeTab", "alarms", "clipboardRead", "clipboardWrite", "menus", "publicSuffix", "scripting",
    "storage", "unlimitedStorage", "webNavigation",
  ]);
  assert.deepEqual(manifest.optional_host_permissions, ["*://*/*"]);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.optional_permissions, undefined);
  assert.equal(manifest.content_scripts, undefined, "the save watcher is registered only when turned on");
});

test("the content security policy, and nothing that lets a page reach the extension", () => {
  assert.deepEqual(manifest.content_security_policy, { extension_pages: "script-src 'self' 'wasm-unsafe-eval'" });
  assert.deepEqual(manifest.web_accessible_resources, []);
  assert.equal(manifest.externally_connectable, undefined);
  assert.equal(manifest.update_url, undefined);
});

test("an event page background script, and no service worker", () => {
  assert.deepEqual(manifest.background, { scripts: ["background.js"] });
});

test("the pages load only packaged scripts and styles, with no inline script or handlers", () => {
  for (const f of readdirSync(join(root, "static")).filter((n) => n.endsWith(".html"))) {
    const html = readFileSync(join(root, "static", f), "utf8");
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    assert.ok(scripts.length > 0, f);
    for (const [, attrs, body] of scripts) {
      const src = attrs.match(/\bsrc="([^"]+)"/)?.[1];
      assert.ok(src !== undefined && /^[\w.-]+\.js$/.test(src), `${f}: script src ${src}`);
      assert.equal(body.trim(), "", `${f}: inline script`);
    }
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${f}: inline event handler`);
    for (const [, href] of html.matchAll(/\bhref="([^"]+)"/g)) assert.match(href, /^[\w.-]+$/, `${f}: ${href}`);
  }
});

/** Problems in a bundle's code: string evaluation or remote script loading. Comments and the text
 * of string literals are blanked first, so that, for example, the glue's debug text
 * `Function(${name})` is not taken for a call. */
function codeProblems(text: string): string[] {
  const code = text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:\\])\/\/.*$/gm, "$1")
    .replace(/`(?:\\[\s\S]|\$\{[^}]*\}|[^`\\])*`|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g, '""');
  const checks: [string, RegExp, string][] = [
    ["eval", /\beval\s*\(/, code],
    ["Function constructor", /\bnew\s+Function\s*\(|(?<![.\w$])Function\s*\(/, code],
    ["timer with a string", /\bset(?:Timeout|Interval)\s*\(\s*""/, code],
    ["dynamic script loading", /\bimportScripts\s*\(|\bimport\s*\(/, code],
    ["remote script URL", /["'`]https?:\/\/[^"'`]*\.m?js\b/, text],
  ];
  return checks.filter(([, re, where]) => re.test(where)).map(([name]) => name);
}

test("the bundle check finds what it looks for, and not the glue's debug text", () => {
  assert.deepEqual(codeProblems("const f = new Function('return 1');"), ["Function constructor"]);
  assert.deepEqual(codeProblems("x = Function('a', 'return a');"), ["Function constructor"]);
  assert.deepEqual(codeProblems("window.eval(code); eval (x);"), ["eval"]);
  assert.deepEqual(codeProblems('setTimeout("alert(1)", 10);'), ["timer with a string"]);
  assert.deepEqual(codeProblems("await import(url);"), ["dynamic script loading"]);
  assert.deepEqual(codeProblems('s.src = "https://cdn.example/lib.js";'), ["remote script URL"]);
  assert.deepEqual(codeProblems("return `Function(${name})`; // eval(x)\n/* new Function() */ obj.Function(1);"), []);
  assert.deepEqual(codeProblems('const msg = "do not eval(this)"; setTimeout(fn, 10);'), []);
});

test("no bundle evaluates code from strings or loads remote script", async () => {
  const out = await esbuild.build({ ...esbuildOptions(currentGlue()), write: false, outdir: join(root, "dist") });
  const files = out.outputFiles!;
  assert.equal(files.length, 4);
  for (const file of files) {
    const name = file.path.slice(file.path.lastIndexOf("/") + 1);
    assert.deepEqual(codeProblems(file.text), [], name);
  }
});
