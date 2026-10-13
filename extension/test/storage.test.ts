import "fake-indexeddb/auto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { hex, Store, unhex, type LockFn } from "../src/shared/storage.ts";

/** A one-holder lock like navigator.locks, recording how many callbacks ran at once. */
function makeLock(): { lock: LockFn; maxHeld: () => number } {
  let tail: Promise<unknown> = Promise.resolve();
  let held = 0;
  let max = 0;
  const lock: LockFn = (_name, fn) => {
    const run = tail.then(async () => {
      held++;
      max = Math.max(max, held);
      try {
        return await fn();
      } finally {
        held--;
      }
    });
    tail = run.catch(() => {});
    return run;
  };
  return { lock, maxHeld: () => max };
}

let n = 0;
const fresh = (lock: LockFn) => {
  // Each test uses its own database name through a separate IDBFactory instance.
  const factory = new (globalThis as unknown as { IDBFactory: new () => IDBFactory }).IDBFactory();
  n++;
  return new Store(factory, lock);
};

test("a commit sees the state on disk and writes state, keys, and config in one transaction", async () => {
  const { lock } = makeLock();
  const store = fresh(lock);
  assert.equal(await store.readState(), null);
  const key = Uint8Array.from({ length: 16 }, (_, i) => i);
  await store.commit((onDisk, host) => {
    assert.equal(onDisk, null);
    host.writeState("state-1");
    host.storeCurrent("v1", key);
    host.storePending("v1", key);
    host.writeConfig({ url: "https://nas.lan:8443", token: "T", fp: null, permission: "https://nas.lan/*", deviceId: key });
  });
  key.fill(0); // the store kept its own copy
  assert.equal(await store.readState(), "state-1");
  const keys = await store.readSecretKeys("v1");
  assert.equal(hex(keys.current!), "000102030405060708090a0b0c0d0e0f");
  assert.equal(hex(keys.pending!), "000102030405060708090a0b0c0d0e0f");
  assert.equal((await store.readConfig())?.permission, "https://nas.lan/*");
  await store.commit((onDisk, host) => {
    assert.equal(onDisk, "state-1");
    host.deletePending("v1");
  });
  assert.equal((await store.readSecretKeys("v1")).pending, null);
});

test("a commit that throws writes nothing", async () => {
  const store = fresh(makeLock().lock);
  await store.commit((_, host) => host.writeState("good"));
  await assert.rejects(
    store.commit((_, host) => {
      host.writeState("half");
      host.storeCurrent("v1", new Uint8Array(16));
      throw new Error("commit rule refused");
    }),
    /commit rule refused/,
  );
  assert.equal(await store.readState(), "good");
  assert.equal((await store.readSecretKeys("v1")).current, null);
});

test("commits run one at a time under the lock and each sees the previous one", async () => {
  const { lock, maxHeld } = makeLock();
  const store = fresh(lock);
  await store.commit((_, host) => host.writeState("0"));
  await Promise.all(Array.from({ length: 20 }, () => store.commit((onDisk, host) => host.writeState(String(Number(onDisk) + 1)))));
  assert.equal(await store.readState(), "20");
  assert.equal(maxHeld(), 1);
});

test("clear removes everything", async () => {
  const store = fresh(makeLock().lock);
  await store.commit((_, host) => {
    host.writeState("s");
    host.storeCurrent("v", new Uint8Array(16));
  });
  await store.clear();
  assert.equal(await store.readState(), null);
  assert.equal((await store.readSecretKeys("v")).current, null);
});

test("hex round trip, and unhex refuses anything but lowercase pairs", () => {
  const b = Uint8Array.from([0, 1, 254, 255]);
  assert.deepEqual(unhex(hex(b)), b);
  assert.throws(() => unhex("ABCD"));
  assert.throws(() => unhex("abc"));
});

void n;
