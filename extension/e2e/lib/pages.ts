// Web pages for the end-to-end tests, served on one port for several host names. Firefox maps the
// names in HOSTS to loopback through network.dns.localDomains, so www.example.com and
// login.example.com are same-site and cross-origin, other.test is cross-site, and nas.lan has no
// known public suffix (a local host).

import { createServer, type Server } from "node:http";

export const HOSTS = [
  "www.example.com", "login.example.com", "other.test", "nas.lan", "frames.test",
  ...Array.from({ length: 12 }, (_, i) => `o${i + 1}.test`),
];

const form = (prefix: string) => `
<form id="${prefix}form" method="post" action="/done">
  <input id="${prefix}user" name="user" type="text" autocomplete="username">
  <input id="${prefix}pass" name="pass" type="password" autocomplete="current-password">
  <button id="${prefix}submit" type="submit">Sign in</button>
</form>`;

function html(body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>test</title></head><body>${body}</body></html>`;
}

export class Pages {
  private server: Server;
  readonly port: number;

  private constructor(server: Server, port: number) {
    this.server = server;
    this.port = port;
  }

  url(host: string, path: string, scheme = "http"): string {
    return `${scheme}://${host}:${this.port}${path}`;
  }

  static async start(): Promise<Pages> {
    const server = createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://x");
      const port = (server.address() as { port: number }).port;
      const at = (host: string, path: string) => `http://${host}:${port}${path}`;
      let body: string | null = null;
      switch (u.pathname) {
        case "/login.html":
          body = form("");
          break;
        case "/frame.html":
          body = form("f-");
          break;
        case "/frame2.html":
          body = `<p>second page</p>${form("f2-")}`;
          break;
        case "/frames.html":
          body = `${form("")}
            <iframe id="same" src="/frame.html"></iframe>
            <iframe id="site" src="${at("login.example.com", "/frame.html")}"></iframe>
            <iframe id="xsite" src="${at("other.test", "/frame.html")}"></iframe>
            <iframe id="nav" src="/frame.html"></iframe>`;
          break;
        case "/decoy.html":
          // Password fields a person cannot see come before the real form.
          body = `<form id="decoy">
              <input id="decoy-user" type="text" style="opacity: 0.01">
              <input id="decoy-pass" type="password" style="position: absolute; left: -9999px">
              <input id="decoy-tiny" type="password" style="width: 1px; height: 1px; padding: 0; border: 0">
              <div style="overflow: hidden; width: 1px; height: 1px"><input id="decoy-clipped" type="password"></div>
              <div style="position: relative"><input id="decoy-covered" type="password">
                <div style="position: absolute; inset: -5px; background: white"></div></div>
            </form>${form("")}`;
          break;
        case "/frames2.html": {
          const inner = encodeURIComponent(form("d-"));
          body = `${form("")}
            <iframe id="srcdoc" srcdoc="${form("s-").replace(/"/g, "&quot;")}"></iframe>
            <iframe id="blank"></iframe>
            <iframe id="data" src="data:text/html,${inner}"></iframe>
            <iframe id="sandboxed" sandbox="allow-scripts allow-forms" src="/frame.html"></iframe>
            <script>document.getElementById("blank").contentDocument.body.innerHTML = ${JSON.stringify(form("b-"))};</script>`;
          break;
        }
        case "/subframe.html":
          body = `<p>a login form in a same-origin frame</p><iframe id="sub" src="/frame.html"></iframe>`;
          break;
        case "/signup.html":
          body = `<form method="post" action="/done"><input id="user" type="text">
            <input id="new" type="password" autocomplete="new-password"><input id="again" type="password">
            <button id="submit">Sign up</button></form>`;
          break;
        case "/done":
          body = "<p id='done'>signed in</p>";
          break;
      }
      if (body === null) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }).end(html(body));
    });
    await new Promise<void>((ok) => server.listen(0, "::", ok));
    return new Pages(server, (server.address() as { port: number }).port);
  }

  stop(): Promise<void> {
    return new Promise((ok) => this.server.close(() => ok()));
  }
}
