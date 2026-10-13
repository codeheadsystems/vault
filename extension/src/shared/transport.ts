// Requests to vault serve (docs/firefox.md, Background script): no redirects, no cookies or other
// credentials, and no HTTP cache. A transport failure or a timeout becomes "unreachable".

import type { Input, Step } from "vault-wasm";

export type RequestStep = Extract<Step, { type: "request" }>;

export interface Server {
  url: string;
  token: string;
}

export const TIMEOUT_MS = 30_000;

/** The URL of an API path under the server URL, keeping any path prefix a reverse proxy adds. */
export function apiUrl(server: string, path: string): string {
  return server.replace(/\/+$/, "") + path;
}

export async function send(server: Server, step: RequestStep, fetchImpl: typeof fetch = fetch): Promise<Input> {
  const headers: Record<string, string> = { Authorization: `Bearer ${server.token}` };
  if (step.ifMatch !== undefined) headers["If-Match"] = step.ifMatch;
  if (step.ifNoneMatch !== undefined) headers["If-None-Match"] = step.ifNoneMatch;
  if (step.body !== undefined) headers["Content-Type"] = "application/octet-stream";
  try {
    const response = await fetchImpl(apiUrl(server.url, step.path), {
      method: step.method,
      headers,
      body: step.body as Uint8Array<ArrayBuffer> | undefined,
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const body = new Uint8Array(await response.arrayBuffer());
    const dateHeader = response.headers.get("Date");
    const date = dateHeader === null ? NaN : Date.parse(dateHeader);
    return Number.isNaN(date)
      ? { type: "response", status: response.status, body }
      : { type: "response", status: response.status, body, date };
  } catch {
    return { type: "unreachable" };
  }
}

/** Whether the server answers at all, without the token: any response, a 401 included, means
 * that TLS succeeded (docs/firefox.md, Setup). */
export async function probe(server: string, fetchImpl: typeof fetch = fetch): Promise<boolean> {
  try {
    await fetchImpl(apiUrl(server, "/v1/vault"), {
      method: "GET", redirect: "error", credentials: "omit", cache: "no-store", signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return true;
  } catch {
    return false;
  }
}
