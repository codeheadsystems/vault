// Firefox APIs that @types/firefox-webext-browser does not declare yet.

declare namespace browser.publicSuffix {
  /** The longest public suffix an explicit list rule gives `hostname`, or null. Throws on a host
   * it cannot parse. Firefox 153. */
  function getKnownSuffix(hostname: string): string | null;
  function isKnownSuffix(hostname: string): boolean;
  function getDomain(
    hostname: string,
    options?: {
      encoding?: "punycode" | "display";
      allowIPAddress?: boolean;
      allowPlainSuffix?: boolean;
      allowUnknownSuffix?: boolean;
    },
  ): string | null;
}
