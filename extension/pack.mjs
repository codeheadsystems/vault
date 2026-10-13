// Packs dist/ into artifacts/vault-<version>.xpi, a zip archive, with Node built-ins only. The
// archive is deterministic: files sorted by path, a fixed timestamp, and no extra fields, so the
// same build gives the same bytes. `npm run sign` uploads it.

import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, deflateRawSync } from "node:zlib";

/** 1980-01-01 00:00:00, the zip format's earliest date, in MS-DOS form. */
const DOS_DATE = (0 << 9) | (1 << 5) | 1;
const DOS_TIME = 0;
const UTF8_NAMES = 0x0800;

/**
 * A zip archive of `entries`, each deflated.
 * @param {{ name: string; data: Buffer }[]} entries
 * @returns {Buffer}
 */
export function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    const packed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(UTF8_NAMES, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(UTF8_NAMES, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, packed);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + packed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** Every file under `dir`, as archive paths with forward slashes, sorted. */
function files(dir) {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(relative(dir, p).split(sep).join("/"));
    }
  };
  walk(dir);
  return out.sort();
}

/** Packs `dist` and returns the path of the .xpi. */
export function pack(root = fileURLToPath(new URL(".", import.meta.url))) {
  const dist = join(root, "dist");
  const manifest = JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8"));
  const entries = files(dist).map((name) => ({ name, data: readFileSync(join(dist, ...name.split("/"))) }));
  mkdirSync(join(root, "artifacts"), { recursive: true });
  const out = join(root, "artifacts", `vault-${manifest.version}.xpi`);
  writeFileSync(out, zip(entries));
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(`pack: ${pack()}`);
}
