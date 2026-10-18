/**
 * Glue between console routes, the session cookie and the API client.
 * Loaders call `requireOperator`; actions call `requireMutation`, which also
 * checks the origin and the CSRF token before any API write.
 */

import { data, type RouterContextProvider, redirect } from "react-router";
import { cloudflareContext } from "../context";
import { ApiError, BadIdError, ConsoleApi } from "./api.server";
import {
  clearSessionCookie,
  hasScope,
  openSession,
  readCookie,
  SESSION_COOKIE,
  type SessionData,
  safeEqual,
  sameOrigin,
} from "./session.server";

export interface RouteArgs {
  request: Request;
  context: Readonly<RouterContextProvider>;
}

export interface Operator {
  session: SessionData;
  api: ConsoleApi;
  env: Env;
  can: (scope: string) => boolean;
}

/** Largest form body we parse. Every field is capped again where it is used. */
const MAX_FORM_BYTES = 64 * 1024;

function loginRedirect(request: Request, clear: boolean): Response {
  const url = new URL(request.url);
  const next = `${url.pathname}${url.search}`;
  const to = next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`;
  return redirect(to, clear ? { headers: { "set-cookie": clearSessionCookie() } } : undefined);
}

export async function requireOperator({ request, context }: RouteArgs): Promise<Operator> {
  const { env } = context.get(cloudflareContext);
  const raw = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
  const session = await openSession(raw, env.SESSION_SECRET, Date.now()).catch(() => null);
  if (!session) throw loginRedirect(request, raw !== null);
  return {
    session,
    api: new ConsoleApi(env.API, session.token),
    env,
    can: (scope) => hasScope(session.principal, scope),
  };
}

export interface Mutation extends Operator {
  form: FormData;
}

/** For actions: a valid session, a same-origin POST and the session's CSRF token. */
export async function requireMutation(args: RouteArgs): Promise<Mutation> {
  const op = await requireOperator(args);
  const { request } = args;
  if (request.method !== "POST") throw data({ message: "Method not allowed." }, { status: 405 });
  if (!sameOrigin(request)) throw data({ message: "Cross-site request refused." }, { status: 403 });
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > MAX_FORM_BYTES) throw data({ message: "Form too large." }, { status: 413 });
  const form = await request.formData();
  const csrf = form.get("csrf");
  if (typeof csrf !== "string" || !safeEqual(csrf, op.session.csrf)) {
    throw data(
      { message: "This form has expired. Reload the page and try again." },
      { status: 403 },
    );
  }
  return { ...op, form };
}

/** What a page shows when one API read fails. */
export interface LoadError {
  status: number;
  /** Plain words for the operator. */
  message: string;
  /** The route is planned in the spec but not served yet. */
  notServed: boolean;
}

export type Loaded<T> = { ok: true; data: T } | { ok: false; error: LoadError };

export function describeError(e: unknown): LoadError {
  if (e instanceof BadIdError) {
    return { status: 404, message: `That ${e.kind} id is not valid.`, notServed: false };
  }
  if (e instanceof ApiError) {
    if (e.notServed) {
      return { status: e.status, message: "The API does not serve this yet.", notServed: true };
    }
    const byStatus: Record<number, string> = {
      400: "The API refused the request as invalid.",
      403: "Your token does not have the scope for this.",
      404: "Not found, or not visible to your tenant.",
      409: "The current state does not allow this.",
      413: "The request was too large.",
      422: "The API refused this under its launch rules.",
      429: "Rate limited. Wait and try again.",
    };
    const base = byStatus[e.status] ?? `The API returned an error (${e.status}).`;
    return {
      status: e.status,
      message: e.detail ? `${base} ${e.detail}` : base,
      notServed: false,
    };
  }
  return { status: 502, message: "The API could not be reached.", notServed: false };
}

/**
 * Run one API read for a page. A 401 means the token was revoked or expired:
 * end the session and send the operator to sign in. Anything else becomes a
 * LoadError the page renders in place, so one failing panel never takes the
 * whole console down.
 */
export async function load<T>(request: Request, p: Promise<T>): Promise<Loaded<T>> {
  try {
    return { ok: true, data: await p };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) throw loginRedirect(request, true);
    return { ok: false, error: describeError(e) };
  }
}

/** Like `load`, but for the one read a detail page cannot do without: failures become the route's error. */
export async function must<T>(request: Request, p: Promise<T>): Promise<T> {
  const r = await load(request, p);
  if (!r.ok) throw data(r.error, { status: r.error.status === 502 ? 502 : r.error.status });
  return r.data;
}

/** The result of a form post, rendered next to the form. */
export interface ActionResult {
  ok: boolean;
  message: string;
  /** Which form on the page this answers, so the message lands next to it. */
  form?: string;
}

// ---------- Form field helpers ----------

/** A trimmed string field, capped at `max` characters. Empty becomes undefined. */
export function field(
  form: FormData | URLSearchParams,
  name: string,
  max = 200,
): string | undefined {
  const v = form.get(name);
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t === "" ? undefined : t.slice(0, max);
}

/** A field that must be one of `allowed`. */
export function oneOf<T extends string>(
  form: FormData | URLSearchParams,
  name: string,
  allowed: readonly T[],
): T | undefined {
  const v = field(form, name, 64);
  return v !== undefined && (allowed as readonly string[]).includes(v) ? (v as T) : undefined;
}

/** An integer field within [min, max]. */
export function intField(
  form: FormData | URLSearchParams,
  name: string,
  min: number,
  max: number,
): number | undefined {
  const v = field(form, name, 20);
  if (v === undefined || !/^-?\d+$/.test(v)) return undefined;
  const n = Number(v);
  return n >= min && n <= max ? n : undefined;
}

export const WINDOWS = { "24h": 24 * 3600_000, "7d": 7 * 24 * 3600_000, "31d": 31 * 24 * 3600_000 };
export type WindowKey = keyof typeof WINDOWS;

/**
 * Time window from the URL: `window=24h|7d|31d`, or explicit `since` and
 * `until` (unix ms) passed through from a list page so detail reads match.
 */
export function windowFrom(params: URLSearchParams, now = Date.now()) {
  const since = intField(params, "since", 0, 8_640_000_000_000_000);
  const until = intField(params, "until", 0, 8_640_000_000_000_000);
  if (since !== undefined || until !== undefined) {
    return { key: undefined, since, until };
  }
  const key = oneOf(params, "window", Object.keys(WINDOWS) as WindowKey[]);
  return {
    key: key ?? ("7d" as WindowKey),
    since: key ? now - WINDOWS[key] : undefined,
    until: undefined,
  };
}
