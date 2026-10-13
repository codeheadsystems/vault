// A vault for the end-to-end tests: a real vault serve, a vault created by the CLI, and the
// extension set up against it, unlocked, with a standard set of logins.

import { Ext } from "./ext.ts";
import { Cli, HoldingProxy, VaultServe } from "./serve.ts";

export const PASSWORD = "correct horse battery staple e2e";

export const ITEMS = {
  example: { type: "login", name: "example", username: "ann", password: "pw-example", uris: [{ uri: "http://www.example.com", match: "base_domain" }] },
  secure: { type: "login", name: "secure example", username: "bob", password: "pw-secure", uris: [{ uri: "https://www.example.com", match: "base_domain" }] },
  nas: { type: "login", name: "nas", username: "admin", password: "pw-nas", uris: [{ uri: "https://nas.lan", match: "base_domain" }] },
  other1: { type: "login", name: "other one", username: "o1", password: "pw-o1", uris: [{ uri: "http://other.test", match: "base_domain" }] },
  other2: { type: "login", name: "other two", username: "o2", password: "pw-o2", uris: [{ uri: "http://other.test", match: "base_domain" }] },
  frames: { type: "login", name: "frames", username: "fran", password: "pw-frames", uris: [{ uri: "http://frames.test", match: "base_domain" }] },
} as const;
export type ItemName = keyof typeof ITEMS;

export interface Fixture {
  serve: VaultServe;
  cli: Cli;
  ext: Ext;
  secretKey: string;
  proxy: HoldingProxy | null;
  ids: Record<ItemName, string>;
  stop(): Promise<void>;
}

export interface FixtureOptions {
  /** Add ITEMS through the extension. */
  items?: boolean;
  /** Put a HoldingProxy between the extension and the server. */
  proxy?: boolean;
  /** A profile directory that outlives the session. */
  profile?: string;
  prefs?: Record<string, unknown>;
}

export async function vault(options: FixtureOptions = {}): Promise<Fixture> {
  const serve = await VaultServe.start();
  const cli = new Cli(PASSWORD);
  const secretKey = await cli.init(serve.setupText("cli"));
  const proxy = options.proxy ? await HoldingProxy.start(serve.httpPort) : null;
  const ext = await Ext.start(options.prefs, { profile: options.profile });
  const url = proxy ? `http://localhost:${proxy.port}` : undefined;
  await ext.setup(serve.setupText("firefox", url), secretKey, PASSWORD);
  const ids = {} as Record<ItemName, string>;
  if (options.items !== false) {
    for (const [k, item] of Object.entries(ITEMS)) {
      ids[k as ItemName] = (await ext.request<{ id: string }>({ type: "add", item })).id;
    }
  }
  return {
    serve, cli, ext, secretKey, proxy, ids,
    // `this.ext`: a test may replace the session, as the restart test does.
    async stop(this: Fixture) {
      try {
        await this.ext.stop();
      } finally {
        await proxy?.stop();
        await serve.stop();
        cli.stop();
      }
    },
  };
}
