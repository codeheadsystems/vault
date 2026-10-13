// A real `vault serve`, and the vault CLI as a second device, for the end-to-end tests.
//
// VAULT_BIN names the vault binary; otherwise the tests build crates/vault-cli with cargo and use
// target/debug/vault (or $CARGO_TARGET_DIR/debug/vault). The CLI reads its setup text and the kit
// confirmation from /dev/tty, so it runs under util-linux `script`, which gives it a pty; the
// master password comes through --password-fd from a file readable only by the user.

import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { freePort, waitFor } from "./firefox.ts";

const workspace = resolve(import.meta.dirname, "..", "..", "..");
let built: string | null = null;

export function vaultBin(): string {
  if (process.env.VAULT_BIN) return process.env.VAULT_BIN;
  if (built === null) {
    execFileSync("cargo", ["build", "-q", "-p", "vault-cli"], { cwd: workspace, stdio: "inherit" });
    built = join(process.env.CARGO_TARGET_DIR ?? join(workspace, "target"), "debug", "vault");
  }
  return built;
}

export interface ServeOptions {
  /** An https listener with the generated self-signed certificate, besides the loopback http one. */
  https?: boolean;
}

export class VaultServe {
  readonly dir: string;
  readonly httpPort: number;
  readonly httpsPort: number | null;
  private proc: ChildProcess | null = null;
  log = "";

  private constructor(dir: string, httpPort: number, httpsPort: number | null) {
    this.dir = dir;
    this.httpPort = httpPort;
    this.httpsPort = httpsPort;
  }

  static async start(options: ServeOptions = {}): Promise<VaultServe> {
    const dir = mkdtempSync(join(tmpdir(), "vault-e2e-serve-"));
    const httpPort = await freePort();
    const httpsPort = options.https ? await freePort() : null;
    const s = new VaultServe(dir, httpPort, httpsPort);
    const args = ["serve", "init", "--data", join(dir, "data"), "--http-listen", `127.0.0.1:${httpPort}`];
    if (httpsPort === null) args.push("--no-tls", "--url", `http://localhost:${httpPort}`);
    else args.push("--listen", `127.0.0.1:${httpsPort}`, "--url", `https://localhost:${httpsPort}`);
    execFileSync(vaultBin(), args, { stdio: "ignore" });
    s.proc = spawn(vaultBin(), ["serve", "--data", join(dir, "data")], { stdio: ["ignore", "pipe", "pipe"] });
    s.proc.stdout!.on("data", (d) => (s.log += d));
    s.proc.stderr!.on("data", (d) => (s.log += d));
    await waitFor("vault serve", async () => (await fetch(`http://127.0.0.1:${httpPort}/v1/vault`)).status === 401, 15_000);
    return s;
  }

  /** The setup text of a new token, for `url` (the http listener on localhost by default). */
  setupText(name: string, url = `http://localhost:${this.httpPort}`): string {
    const out = execFileSync(vaultBin(), ["serve", "token", "add", name, "--data", join(this.dir, "data"), "--url", url], { encoding: "utf8" });
    const m = out.match(/vault:\/\/setup\S+/);
    if (!m) throw new Error(`no setup text in: ${out}`);
    return m[0];
  }

  certPem(): string {
    return join(this.dir, "data", "tls", "cert.pem");
  }

  /** Lines of the request log for `token`, such as "GET /v1/vault 200". */
  requests(token: string): string[] {
    return this.log.split("\n").filter((l) => l.trim().split(/\s+/).at(-2) === token).map((l) => l.split(/\s+/).slice(2, 5).join(" "));
  }

  async stop(): Promise<void> {
    this.proc?.kill();
    rmSync(this.dir, { recursive: true, force: true });
  }
}

/** The vault CLI with its own data and configuration directories. */
export class Cli {
  readonly dir: string;
  password: string;

  constructor(password: string) {
    this.dir = mkdtempSync(join(tmpdir(), "vault-e2e-cli-"));
    this.password = password;
  }

  /**
   * Runs `vault <args>` on a pty. `answers` are written when their pattern appears in the output;
   * each may be a function of the output so far.
   */
  run(
    args: string[],
    answers: [RegExp, string | ((out: string) => string)][] = [],
    timeoutMs = 120_000,
    passwordLines: string[] = [this.password, this.password, this.password],
  ): Promise<{ code: number; out: string }> {
    const pw = join(this.dir, "password");
    writeFileSync(pw, passwordLines.map((l) => `${l}\n`).join(""), { mode: 0o600 });
    const quote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
    const command = `${quote(vaultBin())} --password-fd 3 ${args.map(quote).join(" ")} 3<${quote(pw)}`;
    const env = {
      ...process.env,
      XDG_DATA_HOME: join(this.dir, "data"),
      XDG_CONFIG_HOME: join(this.dir, "config"),
      VAULT_NO_AGENT: "1",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/nonexistent",
    };
    return new Promise((ok, fail) => {
      const p = spawn("script", ["-qefc", command, "/dev/null"], { env, stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      const pending = [...answers];
      const timer = setTimeout(() => {
        p.kill();
        fail(new Error(`vault ${args.join(" ")} timed out:\n${out}`));
      }, timeoutMs);
      const onData = (d: Buffer) => {
        out += d.toString();
        for (let i = 0; i < pending.length; i++) {
          const [re, answer] = pending[i];
          if (re.test(out)) {
            p.stdin.write(`${typeof answer === "function" ? answer(out) : answer}\r`);
            pending.splice(i--, 1);
          }
        }
      };
      p.stdout.on("data", onData);
      p.stderr.on("data", onData);
      p.on("exit", (code) => {
        clearTimeout(timer);
        ok({ code: code ?? -1, out: out.replace(/\r/g, "") });
      });
    });
  }

  /** `vault init` against `setupText`; returns the secret key text. */
  async init(setupText: string): Promise<string> {
    const r = await this.run(["init"], [
      [/Setup text/, setupText],
      [/last group/, (out) => out.match(/VLT1-[0-9A-Z-]+/)![0].split("-").at(-1)!],
    ]);
    if (r.code !== 0) throw new Error(`vault init failed:\n${r.out}`);
    return r.out.match(/VLT1-[0-9A-Z-]{39}/)![0];
  }

  stop(): void {
    rmSync(this.dir, { recursive: true, force: true });
  }
}

/**
 * A proxy in front of vault serve's http listener that can hold PUT requests, so that a test can
 * act while a sync's push is in flight.
 */
export class HoldingProxy {
  readonly port: number;
  private server: import("node:http").Server;
  private holding = false;
  private held: (() => void)[] = [];
  /** PUT requests waiting now. */
  get waiting(): number {
    return this.held.length;
  }

  private constructor(server: import("node:http").Server, port: number) {
    this.server = server;
    this.port = port;
  }

  static async start(target: number): Promise<HoldingProxy> {
    const { createServer, request } = await import("node:http");
    let proxy: HoldingProxy;
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const forward = () => {
          const out = request({ host: "127.0.0.1", port: target, path: req.url, method: req.method, headers: req.headers }, (up) => {
            res.writeHead(up.statusCode ?? 502, up.headers);
            up.pipe(res);
          });
          out.on("error", () => res.writeHead(502).end());
          out.end(Buffer.concat(chunks));
        };
        if (req.method === "PUT" && proxy.holding) proxy.held.push(forward);
        else forward();
      });
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    proxy = new HoldingProxy(server, (server.address() as { port: number }).port);
    return proxy;
  }

  hold(): void {
    this.holding = true;
  }

  /** Stops holding and sends every held PUT on. */
  release(): void {
    this.holding = false;
    for (const f of this.held.splice(0)) f();
  }

  stop(): Promise<void> {
    this.release();
    return new Promise((ok) => this.server.close(() => ok()));
  }
}
