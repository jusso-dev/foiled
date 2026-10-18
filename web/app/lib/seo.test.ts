import { describe, expect, it } from "vitest";
import { exampleList } from "../fixtures/public-example";
import { publicMeta, robotsTxt, sitemapXml } from "./seo";

describe("publicMeta", () => {
  it("indexes real pages with a canonical link and Open Graph tags", () => {
    const meta = publicMeta({
      title: "Exploited vulnerabilities",
      description: "Counts.",
      canonical: "https://foiled.example/exploited",
      index: true,
    });
    expect(meta).toContainEqual({ title: "Exploited vulnerabilities · Foiled" });
    expect(meta).toContainEqual({ name: "description", content: "Counts." });
    expect(meta).toContainEqual({ name: "robots", content: "index, follow" });
    expect(meta).toContainEqual({
      tagName: "link",
      rel: "canonical",
      href: "https://foiled.example/exploited",
    });
    expect(meta).toContainEqual({
      property: "og:title",
      content: "Exploited vulnerabilities · Foiled",
    });
    expect(meta).toContainEqual({ property: "og:description", content: "Counts." });
    expect(meta).toContainEqual({ property: "og:type", content: "website" });
  });

  it("does not index a 404 and has no canonical link", () => {
    const meta = publicMeta({
      title: "Not found",
      description: "x",
      canonical: null,
      index: false,
    });
    expect(meta).toContainEqual({ name: "robots", content: "noindex" });
    expect(meta.some((m) => "rel" in m)).toBe(false);
  });

  it("shows bidi characters in titles as escapes", () => {
    const meta = publicMeta({ title: "a‮b", description: "", canonical: null, index: true });
    expect(meta[0]).toEqual({ title: "a\\u{202e}b · Foiled" });
  });
});

describe("robotsTxt", () => {
  it("allows the public pages and disallows everything else", () => {
    const txt = robotsTxt("https://foiled.example");
    expect(txt).toContain("Allow: /exploited\n");
    expect(txt).not.toContain("radar");
    expect(txt).toContain("Disallow: /\n");
    expect(txt).toContain("Sitemap: https://foiled.example/sitemap.xml");
  });
});

describe("sitemapXml", () => {
  it("lists the exploit list and each published page, and not the radar", () => {
    const xml = sitemapXml("https://foiled.example", exampleList.items);
    expect(xml).not.toContain("radar");
    expect(xml).toContain("<loc>https://foiled.example/exploited</loc>");
    for (const item of exampleList.items) {
      expect(xml).toContain(`<loc>https://foiled.example${item.canonical_path}</loc>`);
    }
    expect(xml).toContain("<lastmod>2026-10-11</lastmod>");
  });

  it("skips an item whose canonical path is not a public page path", () => {
    const bad = { ...exampleList.items[0], canonical_path: "/design<x>" };
    const xml = sitemapXml("https://foiled.example", [bad]);
    expect(xml).not.toContain("design");
    expect(xml).not.toContain("<x>");
  });
});

describe("sitemapXml bounds", () => {
  it("lists at most 100 pages", () => {
    const many = Array.from({ length: 150 }, (_, i) => ({
      ...exampleList.items[0],
      canonical_path: `/exploited/page-${i}`,
    }));
    const xml = sitemapXml("https://foiled.example", many);
    expect(xml.match(/<url>/g)).toHaveLength(101);
    expect(xml).not.toContain("page-100");
  });
});
