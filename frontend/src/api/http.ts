export const API_BASE_URL = (import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const SESSION_KEY = "auditor-session-v2";
let bearer = sessionStorage.getItem(SESSION_KEY);

export function setSession(value: string | null) {
  bearer = value;
  if (value) sessionStorage.setItem(SESSION_KEY, value);
  else sessionStorage.removeItem(SESSION_KEY);
}

/** All audit clients share token attachment, expiration and permission handling. */
export async function authFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input, window.location.origin);
  const base = new URL(API_BASE_URL, window.location.origin);
  const headers = new Headers(init.headers);
  const sentToken = bearer;
  const trustedApi = url.origin === base.origin && url.pathname.startsWith(`${base.pathname.replace(/\/$/, "")}/api/`);
  if (trustedApi && sentToken) {
    headers.set("Authorization", `Bearer ${sentToken}`);
  }
  const response = await fetch(input, { ...init, headers, cache: "no-store" });
  if (trustedApi && response.status === 401 && bearer === sentToken) {
    setSession(null);
    window.dispatchEvent(new Event("auth-expired"));
  }
  if (trustedApi && response.status === 403) window.dispatchEvent(new Event("auth-forbidden"));
  return response;
}

export async function authJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await authFetch(`${API_BASE_URL}${path}`, init);
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.detail ?? "The request could not be completed.");
  return body as T;
}
