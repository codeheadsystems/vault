// End-to-end: a local change while a sync's push is in flight. A proxy holds the PUT; the second
// change commits under the state lock meanwhile, and the sync's rerun pushes it.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { vault, type Fixture } from "./lib/fixture.ts";
import { waitFor } from "./lib/firefox.ts";

let f: Fixture;

before(async () => {
  f = await vault({ proxy: true, items: false });
});

after(async () => {
  await f?.stop();
});

test("an add during an in-flight sync with the PUT held keeps both", async () => {
  const proxy = f.proxy!;
  proxy.hold();
  await f.ext.request({ type: "add", item: { type: "note", name: "first, its push held" } });
  await waitFor("the first push is held", async () => proxy.waiting === 1, 30_000);
  await f.ext.request({ type: "add", item: { type: "note", name: "second, during the push" } });
  proxy.release();
  await waitFor("both pushed", async () => (await f.ext.status()).summary?.unpushed === false, 30_000);
  const r = await f.cli.run(["sync"]);
  assert.equal(r.code, 0, r.out);
  for (const name of ["first, its push held", "second, during the push"]) {
    assert.match((await f.cli.run(["find", name])).out, new RegExp(name), name);
  }
  assert.ok(f.serve.requests("firefox").filter((l) => l === "PUT /v1/vault 200").length >= 2, "the rerun pushed again");
});
