/**
 * Which paths a deployment serves (#35). The same Worker build runs twice:
 *
 * - `console`: the operator console, behind Cloudflare Access. Serves every
 *   route, including the public pages.
 * - `public`: the public exploit pages, with no Access policy in
 *   front of it. Serves only the allow-list below and a plain 404 for
 *   everything else, so a console route can never leak onto the open site.
 *
 * The surface comes from the `FOILED_SURFACE` var in wrangler.jsonc. Pure
 * functions only, so the rules are unit tested without a Worker.
 */
import { SLUG_PATTERN } from "./public-types";

export type Surface = "console" | "public";

/**
 * Fail closed: only the exact value "console" gives the console. A missing or
 * mistyped var on the public Worker must not open the console routes.
 */
export function surfaceFrom(value: unknown): Surface {
  return value === "console" ? "console" : "public";
}

/** Public page and resource paths, without React Router's `.data` suffix. */
export function isPublicPagePath(pathname: string): boolean {
  if (pathname === "/exploited") return true;
  if (pathname === "/robots.txt" || pathname === "/sitemap.xml") return true;
  const m = /^\/exploited\/([^/]+)$/.exec(pathname);
  return m !== null && m[1].length <= 80 && SLUG_PATTERN.test(m[1]);
}

/**
 * Strip the single-fetch suffix React Router adds for client data requests:
 * `/exploited.data` is `/exploited`, `/exploited/_.data` is `/exploited/`. Returns
 * null when the path is not a data request.
 */
export function stripDataSuffix(pathname: string): string | null {
  if (pathname.endsWith("/_.data")) return pathname.slice(0, -"_.data".length);
  if (pathname.endsWith(".data")) return pathname.slice(0, -".data".length);
  return null;
}

/**
 * True for paths that belong to the public site: the pages, their data
 * requests and built assets. Used for the guard on the public surface and to
 * pick response headers on both.
 *
 * `/__manifest` is not on the list. React Router's lazy route discovery would
 * answer it with route patches for any path asked for, console routes
 * included. Public pages link with plain anchors, so every navigation is a
 * document request and never needs the manifest.
 */
export function isPublicPath(pathname: string): boolean {
  if (isPublicPagePath(pathname)) return true;
  const data = stripDataSuffix(pathname);
  if (data !== null) {
    return data !== "/robots.txt" && data !== "/sitemap.xml" && isPublicPagePath(data);
  }
  // Hashed client bundles and CSS from the Vite build. Usually served by the
  // assets layer before the Worker runs; listed so a cache miss still works.
  return pathname.startsWith("/assets/") && !pathname.includes("..");
}

export type PublicDecision =
  | { action: "serve" }
  | { action: "redirect"; location: string }
  | { action: "not-found" };

/**
 * What the public surface does with a request path and query. Public pages
 * take no query parameters, so a query on a page or data path redirects to
 * the bare path: every page then has one URL, which is the one the API
 * purges from the cache on publish and withdrawal (#35). Built assets keep
 * their query untouched.
 */
export function publicDecision(pathname: string, search = ""): PublicDecision {
  if (pathname === "/") return { action: "redirect", location: "/exploited" };
  if (!isPublicPath(pathname)) return { action: "not-found" };
  if (search !== "" && search !== "?" && !pathname.startsWith("/assets/")) {
    return { action: "redirect", location: pathname };
  }
  return { action: "serve" };
}
