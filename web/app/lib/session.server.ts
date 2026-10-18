/**
 * Operator sessions for the console Worker (docs/ui/console.md#sign-in-and-sessions).
 *
 * The operator's API token lives only inside an encrypted, httpOnly cookie:
 * AES-256-GCM with a key derived (HKDF-SHA-256) from the `SESSION_SECRET`
 * Worker secret. The browser can neither read nor change it, and no token is
 * ever put in the client bundle, a loader response or localStorage. Each
 * session carries a random CSRF token that every mutating form must echo.
 */

import type { Principal } from "./api-types";

export const SESSION_COOKIE = "__Host-foiled_session";
/** Absolute session lifetime. The API token may expire sooner; the API then answers 401. */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const MIN_SECRET_LENGTH = 32;

const AAD = new TextEncoder().encode("foiled-console-session-v1");

export interface SessionData {
  v: 1;
  /** Random session id, the key for server-side revocation at sign-out. */
  sid: string;
  token: string;
  principal: Principal;
  csrf: string;
  /** Unix ms. */
  iat: number;
  /** Unix ms. */
  exp: number;
}

export class SessionConfigError extends Error {
  constructor() {
    super("SESSION_SECRET is missing or shorter than 32 characters");
    this.name = "SessionConfigError";
  }
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function sessionKey(secret: string | undefined): Promise<CryptoKey> {
  if (!secret || secret.length < MIN_SECRET_LENGTH) throw new SessionConfigError();
  let key = keyCache.get(secret);
  if (!key) {
    key = (async () => {
      const base = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        "HKDF",
        false,
        ["deriveKey"],
      );
      return crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new TextEncoder().encode("foiled-console"),
          info: new TextEncoder().encode("session-cookie-aes-gcm"),
        },
        base,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    })();
    keyCache.set(secret, key);
  }
  return key;
}

function toB64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64Url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** 32 random bytes, base64url. Used for CSRF tokens and idempotency keys. */
export function randomToken(): string {
  return toB64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function newSession(token: string, principal: Principal, now: number): SessionData {
  return {
    v: 1,
    sid: randomToken(),
    token,
    principal,
    csrf: randomToken(),
    iat: now,
    exp: now + SESSION_TTL_MS,
  };
}

export async function sealSession(data: SessionData, secret: string | undefined): Promise<string> {
  const key = await sessionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(data));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, plain),
  );
  const out = new Uint8Array(iv.length + sealed.length);
  out.set(iv);
  out.set(sealed, iv.length);
  return toB64Url(out);
}

function isSession(v: unknown): v is SessionData {
  if (typeof v !== "object" || v === null) return false;
  const s = v as Record<string, unknown>;
  const p = s.principal as Record<string, unknown> | undefined;
  return (
    s.v === 1 &&
    typeof s.sid === "string" &&
    typeof s.token === "string" &&
    typeof s.csrf === "string" &&
    typeof s.iat === "number" &&
    typeof s.exp === "number" &&
    typeof p === "object" &&
    p !== null &&
    typeof p.id === "string" &&
    typeof p.tenant_id === "string" &&
    Array.isArray(p.scopes)
  );
}

/** Decrypt a cookie value. Null when it is missing, tampered with, from another key or expired. */
export async function openSession(
  value: string | undefined | null,
  secret: string | undefined,
  now: number,
): Promise<SessionData | null> {
  // A sealed session is well under 4 KB; refuse anything larger before decoding.
  if (!value || value.length > 4096) return null;
  const bytes = fromB64Url(value);
  if (!bytes || bytes.length < 29) return null;
  try {
    const key = await sessionKey(secret);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: AAD },
      key,
      bytes.slice(12),
    );
    const data: unknown = JSON.parse(new TextDecoder().decode(plain));
    if (!isSession(data) || data.exp <= now || data.iat > now + 60_000) return null;
    return data;
  } catch (e) {
    if (e instanceof SessionConfigError) throw e;
    return null;
  }
}

/** Read one cookie from a Cookie header. */
export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/**
 * `__Host-` pins the cookie to this host and path `/` and requires Secure.
 * SameSite=Strict keeps it off cross-site requests, so a forged form post
 * from another site arrives without a session at all.
 */
export function sessionCookie(value: string, maxAgeMs: number): string {
  const maxAge = Math.max(0, Math.floor(maxAgeMs / 1000));
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/** Constant-time string comparison for CSRF tokens. */
export function safeEqual(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

/**
 * Same-origin check for a state-changing request. Browsers send `Origin` on
 * every POST; `Sec-Fetch-Site` backs it up. Either one naming another site
 * fails the request.
 */
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return false;
  if (origin === null) return site === "same-origin";
  return origin === new URL(request.url).origin;
}

/** Whether the session's token holds a scope. `admin` implies every operator scope. */
export function hasScope(principal: Principal, scope: string): boolean {
  return principal.scopes.includes(scope) || principal.scopes.includes("admin");
}
