import { describe, expect, it } from "vitest";
import {
  CONSOLE_CACHE,
  NOT_FOUND_CACHE,
  PUBLIC_CACHE,
  PUBLIC_CSP,
  publicHeaders,
  publicNotFound,
  publicRateLimited,
  publicRedirect,
  publicRouteHeaders,
  withConsoleHeaders,
  withPublicDefaults,
} from "./http-headers";

describe("public headers", () => {
  it("uses the success cache policy and the security headers", () => {
    const h = publicHeaders();
    expect(h.get("Cache-Control")).toBe("public, max-age=60, s-maxage=60");
    expect(h.get("Cache-Control")).not.toContain("stale");
    expect(h.get("X-Content-Type-Options")).toBe("nosniff");
    expect(h.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(h.get("X-Frame-Options")).toBe("DENY");
    expect(h.get("Content-Security-Policy")).toBe(PUBLIC_CSP);
  });

  it("has a CSP that allows React Router SSR and nothing from other origins", () => {
    for (const d of [
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
    ]) {
      expect(PUBLIC_CSP).toContain(d);
    }
    expect(PUBLIC_CSP).not.toMatch(/https?:|\*/);
  });

  it("keeps a loader's 404 cache policy and defaults to the success policy", () => {
    const notFound = new Headers({ "Cache-Control": NOT_FOUND_CACHE });
    expect(publicRouteHeaders({ loaderHeaders: notFound }).get("Cache-Control")).toBe(
      "public, max-age=60",
    );
    expect(publicRouteHeaders({ loaderHeaders: new Headers() }).get("Cache-Control")).toBe(
      PUBLIC_CACHE,
    );
  });

  it("fills gaps without overriding a route's own headers", () => {
    const own = withPublicDefaults(
      new Response("ok", { headers: { "Cache-Control": NOT_FOUND_CACHE } }),
    );
    expect(own.headers.get("Cache-Control")).toBe(NOT_FOUND_CACHE);
    expect(own.headers.get("X-Frame-Options")).toBe("DENY");
    const bare = withPublicDefaults(new Response("error", { status: 500 }));
    expect(bare.status).toBe(500);
    expect(bare.headers.get("Cache-Control")).toBe("no-store");
    expect(bare.headers.get("Content-Security-Policy")).toBe(PUBLIC_CSP);
  });

  it("never caches an error, even when the route set the success policy", () => {
    for (const status of [500, 502, 503, 400, 405]) {
      const res = withPublicDefaults(
        new Response("error", { status, headers: { "Cache-Control": PUBLIC_CACHE } }),
      );
      expect(res.headers.get("Cache-Control"), String(status)).toBe("no-store");
    }
    const ok = withPublicDefaults(
      new Response("ok", { headers: { "Cache-Control": PUBLIC_CACHE } }),
    );
    expect(ok.headers.get("Cache-Control")).toBe(PUBLIC_CACHE);
  });

  it("returns a plain, noindex 404 and a cacheable redirect", async () => {
    const res = publicNotFound();
    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Type")).toContain("text/plain");
    expect(res.headers.get("Cache-Control")).toBe(NOT_FOUND_CACHE);
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
    expect(await res.text()).toBe("Not found\n");
    const r = publicRedirect("/exploited");
    expect(r.status).toBe(302);
    expect(r.headers.get("Location")).toBe("/exploited");
  });
});

describe("publicRateLimited", () => {
  it("returns an uncached 429 with Retry-After", async () => {
    const res = publicRateLimited();
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("60");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(await res.text()).toBe("Too many requests\n");
  });
});

describe("withConsoleHeaders", () => {
  it("marks console responses private, unstored and unindexed", async () => {
    const res = withConsoleHeaders(
      new Response("console", { status: 200, headers: { "Cache-Control": "public, max-age=999" } }),
    );
    expect(res.headers.get("Cache-Control")).toBe(CONSOLE_CACHE);
    expect(res.headers.get("Cache-Control")).toBe("private, no-store");
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
    expect(await res.text()).toBe("console");
  });
});
