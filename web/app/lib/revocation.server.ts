/**
 * Server-side session revocation (docs/ui/console.md#sign-in-and-sessions).
 * Signing out records the session id in a Durable Object named after it
 * (`SessionRevocations`, workers/session-revocations.ts) until the session
 * would have expired, and every request checks it, so a copied cookie stops
 * working at sign-out instead of at expiry.
 */

import type { SessionData } from "./session.server";

/** The RPC surface of one `SessionRevocations` object. */
export interface RevocationStub {
  isRevoked(): Promise<boolean>;
  revoke(expiresAt: number): Promise<void>;
}

interface Namespace {
  idFromName(name: string): unknown;
  get(id: unknown): RevocationStub;
}

export interface RevocationEnv {
  SESSION_REVOCATIONS?: unknown;
  CONSOLE_ENV?: string;
}

function stubFor(env: RevocationEnv, sid: string): RevocationStub | null {
  const ns = env.SESSION_REVOCATIONS as Namespace | undefined;
  if (!ns) return null;
  return ns.get(ns.idFromName(`session:${sid}`));
}

/**
 * Whether a session was signed out. Without the binding the console cannot
 * tell, so it treats every session as revoked, except in explicit
 * development mode.
 */
export async function isRevoked(env: RevocationEnv, session: SessionData): Promise<boolean> {
  const stub = stubFor(env, session.sid);
  if (!stub) return env.CONSOLE_ENV !== "development";
  return stub.isRevoked();
}

export async function revokeSession(env: RevocationEnv, session: SessionData): Promise<void> {
  await stubFor(env, session.sid)?.revoke(session.exp);
}
