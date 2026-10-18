import { describe, expect, it } from "vitest";
import { isPublicPath, publicDecision, stripDataSuffix, surfaceFrom } from "./surface";

describe("surfaceFrom", () => {
  it("gives the console only for the exact value console", () => {
    expect(surfaceFrom("console")).toBe("console");
    expect(surfaceFrom("public")).toBe("public");
  });

  it("fails closed to public for a missing or unknown value", () => {
    for (const v of [undefined, null, "", "Console", "console ", "admin", 1]) {
      expect(surfaceFrom(v)).toBe("public");
    }
  });
});

describe("stripDataSuffix", () => {
  it("removes React Router's single-fetch suffix", () => {
    expect(stripDataSuffix("/exploited.data")).toBe("/exploited");
    expect(stripDataSuffix("/exploited/a-b.data")).toBe("/exploited/a-b");
    expect(stripDataSuffix("/_.data")).toBe("/");
    expect(stripDataSuffix("/exploited")).toBeNull();
  });
});

describe("publicDecision", () => {
  it.each([
    "/exploited",
    "/exploited/examplevpn-path-traversal",
    "/robots.txt",
    "/sitemap.xml",
    "/exploited.data",
    "/exploited/examplevpn-path-traversal.data",
    "/assets/root-AbC123.js",
    "/assets/root-AbC123.css",
  ])("serves %s", (path) => {
    expect(publicDecision(path)).toEqual({ action: "serve" });
  });

  it("drops query strings so each page has one cacheable URL", () => {
    expect(publicDecision("/exploited/demo-page", "?utm=x")).toEqual({
      action: "redirect",
      location: "/exploited/demo-page",
    });
    expect(publicDecision("/exploited/demo-page.data", "?_routes=x")).toEqual({
      action: "redirect",
      location: "/exploited/demo-page.data",
    });
    expect(publicDecision("/sitemap.xml", "?a=1")).toEqual({
      action: "redirect",
      location: "/sitemap.xml",
    });
    expect(publicDecision("/exploited/demo-page", "")).toEqual({ action: "serve" });
    expect(publicDecision("/assets/app-abc.js", "?v=1")).toEqual({ action: "serve" });
    expect(publicDecision("/design", "?x=1")).toEqual({ action: "not-found" });
  });

  it("redirects the root to the exploit list", () => {
    expect(publicDecision("/")).toEqual({ action: "redirect", location: "/exploited" });
  });

  it.each([
    "/design",
    "/design.data",
    "/_.data",
    "/home",
    "/api/v0/tenants",
    "/v0/public/radar",
    "/exploited/",
    "/exploited/_.data",
    "/exploited/Upper-Case",
    "/exploited/a/b",
    "/exploited/..%2fdesign",
    "/radar",
    "/radar.data",
    "/radar/",
    "/radar/extra",
    "/__manifest",
    "/robots.txt.data",
    "/sitemap.xml.data",
    "/assets/../design",
    "/assetsx/a.js",
    "/__manifest/x",
    "/favicon.ico",
  ])("returns 404 for %s", (path) => {
    expect(publicDecision(path)).toEqual({ action: "not-found" });
  });
});

describe("isPublicPath", () => {
  it("treats console routes as non-public", () => {
    expect(isPublicPath("/")).toBe(false);
    expect(isPublicPath("/design")).toBe(false);
    expect(isPublicPath("/radar")).toBe(false);
    expect(isPublicPath("/__manifest")).toBe(false);
    expect(isPublicPath("/exploited")).toBe(true);
  });
});
