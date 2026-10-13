// The fill script (docs/firefox.md, Fill). scripting.executeScript serialises this function and
// runs it in the isolated world of one frame, so it must not refer to anything outside its own
// body: no imports, no module-level helpers. It is synchronous, so the origin check and the writes
// apply to the same document, and it keeps no reference to the credential once it returns.

export type FillMode = "login" | "generate";

export interface FillResult {
  /** Whether the frame's origin was the expected one. */
  origin: boolean;
  usernameFilled: boolean;
  passwordsFilled: number;
}

/**
 * Writes a credential into the visible login fields of this frame's document.
 *
 * - `expectedOrigin` is the top frame's origin; nothing is written when `self.origin` differs.
 *   `self.origin` is used because `location.origin` is "null" in about:blank and srcdoc frames
 *   that inherit the page's origin.
 * - "login" writes `username` into the username field before the first visible password field
 *   (or into a lone username field on a username-first page) and `password` into that password
 *   field.
 * - "generate" writes `password` into the focused password field, or the first visible one, and
 *   into any other visible empty password field of the same form, such as a confirmation field.
 */
export function fillFrame(expectedOrigin: string, username: string, password: string, mode: FillMode): FillResult {
  const result = { origin: false, usernameFilled: false, passwordsFilled: 0 };
  if (self.origin !== expectedOrigin) return result;
  result.origin = true;

  const textTypes = ["text", "email", "tel", ""];
  const MIN = 4; // px: smaller fields are not visible to a person
  /** The part of `a` inside `b`, as [left, top, right, bottom]. */
  const intersect = (a: number[], b: number[]) => [Math.max(a[0], b[0]), Math.max(a[1], b[1]), Math.min(a[2], b[2]), Math.min(a[3], b[3])];
  const big = (r: number[]) => r[2] - r[0] >= MIN && r[3] - r[1] >= MIN;
  const box = (r: DOMRect) => [r.left, r.top, r.right, r.bottom];
  /**
   * A field a person can see and use: enabled and writable; at least 4 by 4 px; inside the
   * document; not transparent (opacity below 0.1 on it or any ancestor); not clipped away by an
   * ancestor's overflow, by `clip`, or by any `clip-path`; and, when its centre is in the viewport,
   * not covered by another element there. A field outside the viewport passes the covered check,
   * because scrolling it into view would change the page.
   */
  const visible = (el: HTMLInputElement): boolean => {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    if (typeof el.checkVisibility === "function" && !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
    const rect = el.getBoundingClientRect();
    let shown = box(rect);
    if (!big(shown)) return false;
    const root = document.documentElement;
    const docBox = [
      -scrollX, -scrollY,
      Math.max(root.scrollWidth, root.clientWidth, innerWidth) - scrollX,
      Math.max(root.scrollHeight, root.clientHeight, innerHeight) - scrollY,
    ];
    shown = intersect(shown, docBox);
    if (!big(shown)) return false;
    for (let node: Element | null = el; node !== null; node = node.parentElement) {
      const s = getComputedStyle(node);
      // An empty value is the property's initial value.
      if (s.opacity !== "" && Number(s.opacity) < 0.1) return false;
      if (s.visibility === "hidden" || s.display === "none") return false;
      if (s.clipPath !== "" && s.clipPath !== "none") return false;
      const clip = /^rect\(\s*(-?[\d.]+)px,?\s+(-?[\d.]+)px,?\s+(-?[\d.]+)px,?\s+(-?[\d.]+)px\s*\)$/.exec(s.clip ?? "");
      if (clip !== null) {
        const r = node.getBoundingClientRect();
        shown = intersect(shown, [r.left + Number(clip[4]), r.top + Number(clip[1]), r.left + Number(clip[2]), r.top + Number(clip[3])]);
        if (!big(shown)) return false;
      }
      const clips = (v: string) => v !== "" && v !== "visible";
      if (node !== el && node !== root && node !== document.body && (clips(s.overflow) || clips(s.overflowX) || clips(s.overflowY))) {
        shown = intersect(shown, box(node.getBoundingClientRect()));
        if (!big(shown)) return false;
      }
    }
    const x = (shown[0] + shown[2]) / 2;
    const y = (shown[1] + shown[3]) / 2;
    if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return true;
    const hit = document.elementFromPoint(x, y);
    if (hit === null) return true;
    if (hit === el || el.contains(hit)) return true;
    return Array.from(el.labels ?? []).some((label) => label === hit || label.contains(hit));
  };
  const inputs = Array.from(document.querySelectorAll("input")).filter(visible);
  const passwords = inputs.filter((el) => el.type === "password");
  const autocomplete = (el: HTMLInputElement) => (el.getAttribute("autocomplete") ?? "").toLowerCase();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  const write = (el: HTMLInputElement, value: string) => {
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  if (mode === "generate") {
    const active = document.activeElement;
    const first =
      passwords.find((el) => el === active) ??
      passwords.find((el) => autocomplete(el).includes("new-password")) ??
      passwords[0];
    if (!first) return result;
    write(first, password);
    result.passwordsFilled = 1;
    for (const el of passwords) {
      if (el !== first && el.form === first.form && el.value === "" && !autocomplete(el).includes("current-password")) {
        write(el, password);
        result.passwordsFilled++;
      }
    }
    return result;
  }

  const target = passwords.find((el) => !autocomplete(el).includes("new-password")) ?? passwords[0];
  let userField: HTMLInputElement | undefined;
  if (target) {
    // The last visible text-like field before the password field, in its form when it has one.
    const scope = inputs.filter((el) => textTypes.includes(el.type) && (target.form === null || el.form === target.form));
    for (const el of scope) {
      if (el.compareDocumentPosition(target) & Node.DOCUMENT_POSITION_FOLLOWING) userField = el;
    }
  } else {
    // A username-first page: a field marked as a username or e-mail, or the only text field.
    const texts = inputs.filter((el) => textTypes.includes(el.type));
    userField =
      texts.find((el) => autocomplete(el).includes("username")) ??
      texts.find((el) => el.type === "email") ??
      (texts.length === 1 ? texts[0] : undefined);
  }
  // The username first: some forms react to it, for example by revealing the password field.
  if (userField && username !== "") {
    write(userField, username);
    result.usernameFilled = true;
  }
  if (target) {
    write(target, password);
    result.passwordsFilled = 1;
  }
  return result;
}
