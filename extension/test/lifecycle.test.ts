import assert from "node:assert/strict";
import { test } from "node:test";
import { coalesce, idleExpired, SessionSlot } from "../src/shared/lifecycle.ts";
import { keepOffers, MAX_OFFERS, type Offer } from "../src/shared/session.ts";

const MIN = 60_000;

test("the idle decision: no recorded activity locks; the boundary locks; just before it does not", () => {
  const t = 1_800_000_000_000;
  assert.equal(idleExpired(t, null, 15), true);
  for (const minutes of [1, 15, 1440]) {
    assert.equal(idleExpired(t, t - minutes * MIN + 1, minutes), false, `${minutes}: 1 ms before`);
    assert.equal(idleExpired(t, t - minutes * MIN, minutes), true, `${minutes}: at the boundary`);
    assert.equal(idleExpired(t, t - minutes * MIN - 1, minutes), true, `${minutes}: after`);
  }
  assert.equal(idleExpired(t, t, 1), false, "activity now");
  assert.equal(idleExpired(t, t + 5_000, 1), false, "a clock that stepped back does not lock by itself");
});

class Fake {
  locked = false;
  freed = 0;
  lock() {
    this.locked = true;
  }
  free() {
    this.freed++;
  }
}

test("concurrent cold-start callers get one session from one open", async () => {
  const slot = new SessionSlot<Fake>();
  let opens = 0;
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const open = async () => {
    opens++;
    await gate;
    return new Fake();
  };
  const all = Promise.all(Array.from({ length: 10 }, () => slot.get(open)));
  release();
  const sessions = await all;
  assert.equal(opens, 1);
  assert.ok(sessions.every((s) => s === sessions[0] && s !== null));
  assert.equal(await slot.get(open), sessions[0], "later callers get the same session");
  assert.equal(opens, 1);
});

test("a drop while an open is in flight discards the opened session", async () => {
  const slot = new SessionSlot<Fake>();
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const opened = new Fake();
  const pending = slot.get(async () => {
    await gate;
    return opened;
  });
  slot.drop();
  release();
  assert.equal(await pending, null);
  assert.equal(opened.locked, true);
  assert.equal(opened.freed, 1);
  assert.equal(slot.peek(), null);
});

test("drop locks and frees the open session once; a failed open is retried by the next caller", async () => {
  const slot = new SessionSlot<Fake>();
  const s = (await slot.get(async () => new Fake()))!;
  slot.drop();
  slot.drop();
  assert.equal(s.locked, true);
  assert.equal(s.freed, 1);
  await assert.rejects(slot.get(async () => {
    throw new Error("no key");
  }), /no key/);
  assert.ok(await slot.get(async () => new Fake()));
});

test("coalesce: one run at a time, and requests during a run cause exactly one more", async () => {
  let runs = 0;
  let active = 0;
  let maxActive = 0;
  const gates: (() => void)[] = [];
  const request = coalesce(async () => {
    runs++;
    active++;
    maxActive = Math.max(maxActive, active);
    await new Promise<void>((r) => gates.push(r));
    active--;
  });
  const first = request();
  const during = [request(), request(), request()];
  assert.equal(runs, 1);
  gates.shift()!();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(runs, 2, "one more run for the three requests made during the first");
  gates.shift()!();
  await Promise.all([first, ...during]);
  assert.equal(runs, 2);
  assert.equal(maxActive, 1);
  const later = request();
  gates.shift()!();
  await later;
  assert.equal(runs, 3, "a request after the runs starts a new one");
});

test("offers: one per origin, at most ten, the newest replacing the oldest", () => {
  const offer = (n: number, at = n): Offer => ({ origin: `https://o${n}.example`, pageUrl: `https://o${n}.example/login`, username: "u", password: "p", at });
  let offers: Offer[] = [];
  for (let n = 1; n <= 11; n++) offers = keepOffers(offers, offer(n));
  assert.equal(offers.length, MAX_OFFERS);
  assert.deepEqual(offers.map((o) => o.origin), Array.from({ length: 10 }, (_, i) => `https://o${i + 2}.example`), "o1 dropped");
  offers = keepOffers(offers, { ...offer(5, 100), username: "new" });
  assert.equal(offers.length, MAX_OFFERS);
  assert.equal(offers.filter((o) => o.origin === "https://o5.example").length, 1);
  assert.equal(offers.at(-1)?.username, "new", "the replacement is now the newest");
});
