// Builds the source archive that AMO reviewers need, because the extension ships compiled
// WebAssembly: `git archive` of HEAD, plus extension/BUILD.md with the exact tool versions and the
// commands that rebuild the .xpi. The archive is artifacts/vault-source-<version>.zip, and
// `npm run sign` attaches it.
//
// The working tree must be clean, so that the archive is exactly what was built; set
// VAULT_SOURCE_ALLOW_DIRTY=1 to archive HEAD anyway, for a trial.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: "utf8" }).trim();

/** The text of BUILD.md for the tools this checkout pins. */
export function buildNotes(root) {
  const repo = join(root, "..");
  const toolchain = /channel = "([^"]+)"/.exec(readFileSync(join(repo, "rust-toolchain.toml"), "utf8"))[1];
  const bindgen = /name = "wasm-bindgen"\nversion = "([^"]+)"/.exec(readFileSync(join(repo, "Cargo.lock"), "utf8"))[1];
  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")).packages;
  const npmPkg = (n) => lock[`node_modules/${n}`].version;
  const manifest = JSON.parse(readFileSync(join(root, "static", "manifest.json"), "utf8"));
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  return `# Building the vault Firefox extension

This archive is the source of vault ${pkg.version} for Firefox (\`${manifest.browser_specific_settings.gecko.id}\`),
at commit ${run("git", ["rev-parse", "HEAD"], repo)}. The extension's JavaScript is not minified;
\`vault_wasm_bg.wasm\` is compiled from \`crates/vault-wasm\` and the crates it depends on.

## Tools

| Tool | Version |
| --- | --- |
| Rust | ${toolchain}, with the \`wasm32-unknown-unknown\` target (\`rust-toolchain.toml\`) |
| wasm-bindgen-cli | ${bindgen} (\`cargo install wasm-bindgen-cli --version ${bindgen}\`) |
| Node.js | ${process.version} or a later 22.x |
| npm | ${run("npm", ["--version"], root)} |
| binaryen (wasm-opt) | ${npmPkg("binaryen")}, from \`package-lock.json\` |
| esbuild | ${npmPkg("esbuild")}, from \`package-lock.json\` |

## Commands

From the archive's root:

\`\`\`
cd extension
npm ci
WASM_BINDGEN=wasm-bindgen npm run pack
\`\`\`

\`npm run pack\` runs \`cargo build -p vault-wasm --target wasm32-unknown-unknown --profile wasm\`,
\`wasm-bindgen --target web\`, \`wasm-opt -O3\`, and esbuild, and writes
\`artifacts/vault-${pkg.version}.xpi\`. Its contents match the submitted file apart from AMO's
signature files.
`;
}

/** Writes the source archive and returns its path. */
export function buildSource(root = fileURLToPath(new URL(".", import.meta.url))) {
  const repo = join(root, "..");
  const dirty = run("git", ["status", "--porcelain"], repo);
  if (dirty !== "" && process.env.VAULT_SOURCE_ALLOW_DIRTY !== "1") {
    throw new Error("the working tree has uncommitted changes, so HEAD is not what was built; commit first");
  }
  const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
  mkdirSync(join(root, "artifacts"), { recursive: true });
  const out = join(root, "artifacts", `vault-source-${version}.zip`);
  execFileSync("git", [
    "archive", "--format=zip", "--prefix=vault/",
    `--add-virtual-file=vault/extension/BUILD.md:${buildNotes(root)}`,
    "-o", out, "HEAD",
  ], { cwd: repo });
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    console.log(`source: ${buildSource()}`);
  } catch (e) {
    console.error(`source: ${e.message}`);
    process.exit(1);
  }
}
