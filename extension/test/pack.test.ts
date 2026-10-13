import assert from "node:assert/strict";
import { test } from "node:test";
import { crc32, inflateRawSync } from "node:zlib";
import { zip } from "../pack.mjs";

/** Reads a zip through its central directory, checking each entry's CRC-32. */
function unzip(buf: Buffer): Map<string, Buffer> {
  const end = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(end >= 0, "end of central directory");
  const count = buf.readUInt16LE(end + 10);
  let p = buf.readUInt32LE(end + 16);
  const out = new Map<string, Buffer>();
  for (let i = 0; i < count; i++) {
    assert.equal(buf.readUInt32LE(p), 0x02014b50);
    const crc = buf.readUInt32LE(p + 16);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    assert.equal(buf.readUInt32LE(local), 0x04034b50);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const data = inflateRawSync(buf.subarray(start, start + size));
    assert.equal(crc32(data), crc, name);
    out.set(name, data);
    p += 46 + nameLen;
  }
  return out;
}

test("the archive holds every entry, deflated, with correct CRCs and UTF-8 names", () => {
  const entries = [
    { name: "manifest.json", data: Buffer.from('{"manifest_version":3}') },
    { name: "dir/ünï.txt", data: Buffer.from("x".repeat(10_000)) },
    { name: "empty", data: Buffer.alloc(0) },
  ];
  const files = unzip(zip(entries));
  assert.deepEqual([...files.keys()], entries.map((e) => e.name));
  for (const e of entries) assert.deepEqual(files.get(e.name), e.data);
});

test("the same input gives the same bytes", () => {
  const entries = [{ name: "a.js", data: Buffer.from("console.log(1)") }];
  assert.deepEqual(zip(entries), zip(entries));
});
