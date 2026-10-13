// Holds every npm package in package-lock.json, development tools included, to the licences
// deny.toml allows (docs/firefox.md, Components). There are no exceptions.
//
// An SPDX expression passes when it is satisfiable from the allowed licences: an OR needs one
// side, an AND needs both.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const deny = readFileSync(join(root, "..", "deny.toml"), "utf8");
const allowBlock = deny.match(/\[licenses\][\s\S]*?\nallow = \[([\s\S]*?)\]/);
if (!allowBlock) throw new Error("deny.toml: no [licenses] allow list");
const allowed = new Set([...allowBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]));
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));

/** Whether `expr` is satisfiable when the licences in `ok` are allowed. */
function satisfiable(expr, ok) {
  const tokens = expr.replace(/[()]/g, (p) => ` ${p} `).trim().split(/\s+/);
  let i = 0;
  const primary = () => {
    if (tokens[i] === "(") {
      i++;
      const v = or();
      i++; // ")"
      return v;
    }
    return ok.has(tokens[i++]);
  };
  const and = () => {
    let v = primary();
    while (tokens[i] === "AND") {
      i++;
      v = primary() && v;
    }
    return v;
  };
  const or = () => {
    let v = and();
    while (tokens[i] === "OR") {
      i++;
      v = and() || v;
    }
    return v;
  };
  return or();
}

const failures = [];
for (const [path, meta] of Object.entries(lock.packages)) {
  if (path === "") continue;
  const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
  const licence = typeof meta.license === "string" ? meta.license : null;
  if (licence === null || !satisfiable(licence, allowed)) failures.push(`${name}@${meta.version}: ${licence ?? "no licence"}`);
}
if (failures.length > 0) {
  console.error(`licences: ${failures.length} package(s) with a licence deny.toml does not allow:\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log(`licences: ${Object.keys(lock.packages).length - 1} packages, all allowed`);
