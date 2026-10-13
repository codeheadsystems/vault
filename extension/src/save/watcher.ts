// The save watcher (docs/firefox.md, Save offers): an optional content script, registered only when
// the user turns save offers on. In the top frame, when a form with a non-empty password field
// submits, it sends the username and password to the background script. It receives nothing back
// but a constant reply, and reads nothing from the extension.

(() => {
  if (window !== window.top) return;

  const textTypes = ["text", "email", "tel", ""];

  function credentials(form: HTMLFormElement): { username: string; password: string } | null {
    const inputs = Array.from(form.querySelectorAll("input"));
    const password = inputs.find((el) => el.type === "password" && el.value !== "");
    if (password === undefined) return null;
    let username = "";
    for (const el of inputs) {
      if (el === password) break;
      if (textTypes.includes(el.type) && el.value !== "") username = el.value;
    }
    return { username, password: password.value };
  }

  let last = "";
  /** Reports `form` for an event the user caused: a trusted event, on a page the user has
   * interacted with. A script's dispatched or requestSubmit() submit before any interaction is
   * ignored. */
  function report(e: Event, form: HTMLFormElement | null): void {
    if (!e.isTrusted || !navigator.userActivation?.hasBeenActive) return;
    if (form === null) return;
    const c = credentials(form);
    if (c === null) return;
    // A click on the submit button and the submit event that follows report the same form once.
    const key = `${c.username}\u0000${c.password}`;
    if (key === last) return;
    last = key;
    void browser.runtime.sendMessage({ type: "saveSubmit", username: c.username, password: c.password }).catch(() => {});
  }

  document.addEventListener("submit", (e) => report(e, e.target instanceof HTMLFormElement ? e.target : null), true);
  // Pages that log in with script and never submit the form: a click on its submit button.
  document.addEventListener(
    "click",
    (e) => {
      const button = (e.target as Element | null)?.closest?.("button, input[type=submit]");
      if (button instanceof HTMLButtonElement || button instanceof HTMLInputElement) {
        if (button.type === "submit") report(e, button.form);
      }
    },
    true,
  );
})();
