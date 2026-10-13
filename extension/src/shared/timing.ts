// Delays the background script schedules. An end-to-end test build (VAULT_E2E_TIMING=1, which
// `npm run sign` refuses) shortens them so that the suite does not wait minutes; every other build
// uses the documented values.

declare const __VAULT_E2E_TIMING__: boolean;

const E2E = typeof __VAULT_E2E_TIMING__ !== "undefined" && __VAULT_E2E_TIMING__;

/** The idle check's alarm period (docs/firefox.md: every minute). */
export const IDLE_CHECK_MINUTES = E2E ? 0.05 : 1;
/** The clipboard clear's delay (docs/firefox.md: 45 seconds). */
export const CLIPBOARD_CLEAR_MINUTES = E2E ? 0.1 : 0.75;
/** The periodic sync (docs/firefox.md: every 5 minutes). */
export const SYNC_MINUTES = 5;
