/**
 * Response headers for the public pages and the console (#35).
 *
 * Public routes are cacheable at the edge and carry a strict CSP. Console
 * responses are private, never stored and never indexed. Route modules use
 * `publicRouteHeaders` as their React Router `headers` export; workers/app.ts
 * fills any gaps (error pages, the guard's 404) with the helpers below.
 */

/**
 * Successful public page: one minute in browsers and at the edge, with no
 * stale serving, so a withdrawn page disappears quickly.
 */
export const PUBLIC_CACHE = "public, max-age=60, s-maxage=60";
/** Public 404: short, so a page that becomes visible shows up soon. */
export const NOT_FOUND_CACHE = "public, max-age=60";
/** Console, and any public response without its own cache policy (errors). */
export const CONSOLE_CACHE = "private, no-store";
export const NO_STORE = "no-store";

/**
 * CSP for React Router SSR. Inline scripts carry the hydration data, so
 * script-src needs 'unsafe-inline'; everything else is same-origin only.
 */
export const PUBLIC_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join("; ");

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Content-Security-Policy": PUBLIC_CSP,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
};

/** Security headers plus a cache policy for a public response. */
export function publicHeaders(cacheControl: string = PUBLIC_CACHE): Headers {
  const h = new Headers(SECURITY_HEADERS);
  h.set("Cache-Control", cacheControl);
  return h;
}

/**
 * React Router `headers` export for public routes. A loader sets its own
 * Cache-Control for a 404 (NOT_FOUND_CACHE); otherwise the success policy
 * applies.
 */
export function publicRouteHeaders({ loaderHeaders }: { loaderHeaders: Headers }): Headers {
  return publicHeaders(loaderHeaders.get("Cache-Control") ?? PUBLIC_CACHE);
}

/** Copy a response so its headers can be changed (fetch responses are immutable). */
function mutable(res: Response): Response {
  return new Response(res.body, res);
}

/**
 * Fill in public headers the route did not set. Errors are never stored, so
 * an outage is not cached at the edge: a response without a cache policy (an
 * error boundary) and any error status other than 404 get no-store. The
 * status check matters for `.data` requests, where React Router runs the
 * failing route's `headers` export and would otherwise send the success
 * policy with a 500.
 */
export function withPublicDefaults(res: Response): Response {
  const out = mutable(res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    if (!out.headers.has(k)) out.headers.set(k, v);
  }
  const isError = res.status >= 400 && res.status !== 404;
  if (isError || !out.headers.has("Cache-Control")) out.headers.set("Cache-Control", NO_STORE);
  return out;
}

/** Console responses: private, never stored, never indexed. */
export function withConsoleHeaders(res: Response): Response {
  const out = mutable(res);
  out.headers.set("Cache-Control", CONSOLE_CACHE);
  out.headers.set("X-Robots-Tag", "noindex");
  return out;
}

/** The public surface's plain 404 for any path outside the allow-list. */
export function publicNotFound(): Response {
  const h = publicHeaders(NOT_FOUND_CACHE);
  h.set("Content-Type", "text/plain; charset=utf-8");
  h.set("X-Robots-Tag", "noindex");
  return new Response("Not found\n", { status: 404, headers: h });
}

/** Redirect on the public surface, for example `/` to `/exploited`. */
export function publicRedirect(location: string): Response {
  const h = publicHeaders(PUBLIC_CACHE);
  h.set("Location", location);
  return new Response(null, { status: 302, headers: h });
}

/** Over the public rate limit. Never cached, so one client's 429 is not served to others. */
export function publicRateLimited(): Response {
  const h = publicHeaders(NO_STORE);
  h.set("Content-Type", "text/plain; charset=utf-8");
  h.set("Retry-After", "60");
  h.set("X-Robots-Tag", "noindex");
  return new Response("Too many requests\n", { status: 429, headers: h });
}
