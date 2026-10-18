/**
 * Test harness for console routes: the real route config (app/routes.ts),
 * the real loaders, actions and components, rendered with React Router's
 * static handler against a fake API Worker. No network.
 */

import type { RouteConfigEntry } from "@react-router/dev/routes";
import { renderToString } from "react-dom/server";
import {
  createStaticHandler,
  createStaticRouter,
  Outlet,
  type RouteObject,
  RouterContextProvider,
  StaticRouterProvider,
  UNSAFE_withComponentProps,
  UNSAFE_withErrorBoundaryProps,
} from "react-router";
import { cloudflareContext } from "../context";
import type { Principal } from "../lib/api-types";
import { newSession, SESSION_COOKIE, type SessionData, sealSession } from "../lib/session.server";
import routeConfig from "../routes";

export const ORIGIN = "https://console.test";
export const SECRET = "test-session-secret-0123456789abcdef-not-real";
export const TOKEN = `fo_tok1.${"a".repeat(40)}`;

export interface ApiCall {
  method: string;
  path: string;
  search: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export type Handler = (call: ApiCall) => Response | unknown | undefined;

export const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

export const apiError = (status: number, code: string, message: string) =>
  json({ error: { code, message } }, status);

/** What the real router answers for a planned (unrouted) path. */
export const notServed = () => apiError(404, "not_found", "route not found");

/**
 * A fake `API` Service Binding. `handler` returns a Response, a value to
 * send as JSON, or undefined for "route not found".
 */
export function fakeApi(handler: Handler) {
  const calls: ApiCall[] = [];
  const api = {
    calls,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const call: ApiCall = {
        method: init?.method ?? "GET",
        path: url.pathname,
        search: url.searchParams,
        headers: new Headers(init?.headers),
        body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      };
      calls.push(call);
      const out = handler(call);
      if (out instanceof Response) return out;
      if (out === undefined) return notServed();
      return json(out);
    }) as Fetcher["fetch"],
  };
  return api;
}

export type FakeApi = ReturnType<typeof fakeApi>;

/** Session ids signed out through the fake `SESSION_REVOCATIONS` binding, shared by every env. */
export const revokedSessions = new Set<string>();

const fakeRevocations = {
  idFromName: (name: string) => name,
  get: (name: unknown) => ({
    isRevoked: async () => revokedSessions.has(String(name)),
    revoke: async () => {
      revokedSessions.add(String(name));
    },
  }),
};

export function envWith(api: FakeApi, extra: Partial<Env> = {}): Env {
  return {
    API: api as unknown as Fetcher,
    SESSION_SECRET: SECRET,
    SESSION_REVOCATIONS: fakeRevocations,
    ...extra,
  } as unknown as Env;
}

export const ADMIN: Principal = { id: "tok1", role: "human", tenant_id: "t1", scopes: ["admin"] };

export async function signIn(principal: Principal = ADMIN): Promise<{
  cookie: string;
  session: SessionData;
}> {
  const session = newSession(TOKEN, principal, Date.now());
  return { cookie: `${SESSION_COOKIE}=${await sealSession(session, SECRET)}`, session };
}

// ---------- Route tree from app/routes.ts ----------

const modules = import.meta.glob("../routes/**/*.{ts,tsx}", { eager: true }) as Record<
  string,
  {
    loader?: RouteObject["loader"];
    action?: RouteObject["action"];
    default?: React.ComponentType<never>;
    ErrorBoundary?: React.ComponentType<never>;
  }
>;

function toRoute(c: RouteConfigEntry): RouteObject {
  const id = c.id ?? c.file.replace(/\.tsx?$/, "");
  const m = modules[`../${c.file}`];
  if (!m) throw new Error(`no module for ${c.file}`);
  const base = {
    id,
    loader: m.loader,
    action: m.action,
    Component: m.default ? UNSAFE_withComponentProps(m.default as never) : undefined,
    ErrorBoundary: m.ErrorBoundary
      ? UNSAFE_withErrorBoundaryProps(m.ErrorBoundary as never)
      : undefined,
  };
  if (c.index) return { ...base, index: true } as RouteObject;
  return { ...base, path: c.path, children: c.children?.map(toRoute) } as RouteObject;
}

export const routes: RouteObject[] = [
  { id: "root", path: "/", Component: Outlet, children: routeConfig.map(toRoute) },
];

const fakeCtx = {
  waitUntil() {},
  passThroughOnException() {},
  props: {},
} as unknown as ExecutionContext;

function context(env: Env) {
  const ctx = new RouterContextProvider();
  ctx.set(cloudflareContext, { env, ctx: fakeCtx });
  return ctx;
}

export interface RequestOpts {
  cookie?: string;
  method?: "GET" | "POST";
  form?: Record<string, string | string[]>;
  /** Defaults to the console's own origin. */
  origin?: string | null;
}

export function makeRequest(path: string, opts: RequestOpts = {}): Request {
  const headers = new Headers();
  if (opts.cookie) headers.set("cookie", opts.cookie);
  const method = opts.method ?? (opts.form ? "POST" : "GET");
  let body: URLSearchParams | undefined;
  if (method === "POST") {
    if (opts.origin !== null) headers.set("origin", opts.origin ?? ORIGIN);
    headers.set(
      "sec-fetch-site",
      opts.origin && opts.origin !== ORIGIN ? "cross-site" : "same-origin",
    );
    body = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.form ?? {})) {
      for (const one of Array.isArray(v) ? v : [v]) body.append(k, one);
    }
    headers.set("content-type", "application/x-www-form-urlencoded");
  }
  return new Request(`${ORIGIN}${path}`, { method, headers, body });
}

export type PageResult =
  | { kind: "response"; response: Response }
  | {
      kind: "page";
      status: number;
      html: string;
      actionData: unknown;
      loaderData: Record<string, unknown>;
    };

/** A document request: run loaders (and the action for POST), then render the page. */
export async function page(env: Env, path: string, opts: RequestOpts = {}): Promise<PageResult> {
  const handler = createStaticHandler(routes);
  const result = await handler.query(makeRequest(path, opts), { requestContext: context(env) });
  if (result instanceof Response) return { kind: "response", response: result };
  const router = createStaticRouter(handler.dataRoutes, result);
  const html = renderToString(
    <StaticRouterProvider router={router} context={result} hydrate={false} />,
  );
  const actionData = result.actionData ? Object.values(result.actionData)[0] : undefined;
  return {
    kind: "page",
    status: result.statusCode,
    html,
    actionData,
    loaderData: result.loaderData as Record<string, unknown>,
  };
}

/** Run a hand-built request through the router; returns the status of the page or response. */
export async function rawQuery(env: Env, request: Request): Promise<{ status: number }> {
  const handler = createStaticHandler(routes);
  const result = await handler.query(request, { requestContext: context(env) });
  return { status: result instanceof Response ? result.status : result.statusCode };
}

/** A resource route (no component): the loader or action's own Response. */
export async function resource(
  env: Env,
  path: string,
  routeId: string,
  opts: RequestOpts = {},
): Promise<Response> {
  const handler = createStaticHandler(routes);
  try {
    const out = await handler.queryRoute(makeRequest(path, opts), {
      requestContext: context(env),
      routeId,
    });
    return out instanceof Response ? out : Response.json(out);
  } catch (e) {
    if (e instanceof Response) return e;
    throw e;
  }
}

export function expectPage(r: PageResult): Extract<PageResult, { kind: "page" }> {
  if (r.kind !== "page") {
    throw new Error(
      `expected a page, got ${r.response.status} to ${r.response.headers.get("location")}`,
    );
  }
  return r;
}

export function expectRedirect(r: PageResult): string {
  if (r.kind !== "response") throw new Error(`expected a redirect, got a ${r.status} page`);
  return r.response.headers.get("location") ?? "";
}

/** Visible text of rendered HTML, entities decoded, for wording assertions. */
export function text(html: string): string {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");
}
