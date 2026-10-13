// `npm run start`: a visible Firefox, through geckodriver, with dist/ installed as a temporary
// add-on and the vault page open. The profile is temporary, so every run starts without a vault.
// GECKODRIVER and FIREFOX name the binaries when they are not on PATH. Ctrl+C quits.

import { BASE, Firefox } from "./e2e/lib/firefox.ts";

const ff = await Firefox.start({}, { headless: false });
await ff.installExtension();
await ff.nav(`${BASE}page.html`);
console.log("start: Firefox is running with the extension; Ctrl+C quits.");
const quit = () => void ff.quit().finally(() => process.exit(0));
process.on("SIGINT", quit);
process.on("SIGTERM", quit);
setInterval(() => {}, 1 << 30);
