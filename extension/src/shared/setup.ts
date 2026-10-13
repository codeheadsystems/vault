// Pure helpers for setup (docs/firefox.md, Setup).

/** The fingerprint as the setup text gives it, and as Firefox's certificate viewer shows it. */
export function fingerprintForms(fp: string): { hex: string; colons: string } {
  return { hex: fp, colons: fp.toUpperCase().match(/../g)!.join(":") };
}

/** The host permission for a server URL: its scheme and host, without the port, because Firefox
 * grants a pattern with a port but never matches it. */
export function permissionFor(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.hostname}/*`;
}
