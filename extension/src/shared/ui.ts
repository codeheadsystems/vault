// DOM helpers for the popup and the vault page, and the request client. Text always goes in as
// text nodes, never as markup.

import type { Request, Response } from "./messages.ts";

type Child = Node | string | null | undefined | false;
type Props = Record<string, unknown> & { on?: Record<string, (e: Event) => void> };

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "on") {
      for (const [ev, fn] of Object.entries(v as Record<string, (e: Event) => void>)) el.addEventListener(ev, fn);
    } else if (k === "dataset") {
      Object.assign(el.dataset, v);
    } else if (v !== undefined && v !== null && v !== false) {
      if (k in el && typeof v !== "string") (el as unknown as Record<string, unknown>)[k] = v;
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) el.append(c);
  return el;
}

export function replace(parent: Element, ...children: Child[]): void {
  parent.replaceChildren(...children.filter((c): c is Node | string => c !== null && c !== undefined && c !== false));
}

export class RequestError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Sends a request to the background script and returns its value, or throws its error. */
export async function send<T = unknown>(request: Request): Promise<T> {
  const r = (await browser.runtime.sendMessage(request)) as Response<T> | undefined;
  if (r === undefined) throw new RequestError("no_reply", "The background script did not answer.");
  if (!r.ok) throw new RequestError(r.code, r.message);
  return r.value;
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function openVaultPage(section = ""): void {
  void browser.tabs.create({ url: browser.runtime.getURL("page.html") + (section ? `#${section}` : "") });
}
