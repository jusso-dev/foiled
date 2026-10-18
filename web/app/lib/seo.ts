/**
 * Meta tags for the public pages (#35): title, description, canonical link,
 * robots and Open Graph. Real pages are indexed; 404s are not.
 */
import type { MetaDescriptor } from "react-router";
import { toPrintable } from "./printable";
import { isoDay } from "./public-format";
import { CANONICAL_PATH_PATTERN, type PublicExploitListItem } from "./public-types";

export const SITE_NAME = "Foiled";

export interface PublicMetaInput {
  title: string;
  description: string;
  /** Absolute canonical URL, or null to leave it out (404s). */
  canonical: string | null;
  index: boolean;
  type?: "website" | "article";
}

/** Keep meta descriptions to a length search engines show in full. */
function clip(text: string, max = 200): string {
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

export function publicMeta({
  title,
  description,
  canonical,
  index,
  type = "website",
}: PublicMetaInput): MetaDescriptor[] {
  const t = `${toPrintable(title)} · ${SITE_NAME}`;
  const d = clip(toPrintable(description));
  const out: MetaDescriptor[] = [
    { title: t },
    { name: "description", content: d },
    { name: "robots", content: index ? "index, follow" : "noindex" },
    { property: "og:title", content: t },
    { property: "og:description", content: d },
    { property: "og:type", content: type },
    { property: "og:site_name", content: SITE_NAME },
  ];
  if (canonical) {
    out.push({ tagName: "link", rel: "canonical", href: canonical });
    out.push({ property: "og:url", content: canonical });
  }
  return out;
}

/** Absolute URL for a site path on the origin the request came in on. */
export function absoluteUrl(origin: string, path: string): string {
  return new URL(path, origin).href;
}

/** Crawlers may read the exploit pages and nothing else. */
export function robotsTxt(origin: string): string {
  return [
    "User-agent: *",
    "Allow: /exploited",
    "Disallow: /",
    "",
    `Sitemap: ${new URL("/sitemap.xml", origin).href}`,
    "",
  ].join("\n");
}

function xmlEscape(s: string): string {
  return s.replace(/[<>&'"]/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * Sitemap of the exploit list and every published page. The list endpoint
 * returns at most 100 pages; the slice keeps that bound here too.
 */
export function sitemapXml(origin: string, items: readonly PublicExploitListItem[]): string {
  const url = (path: string, lastmod?: string) =>
    `  <url><loc>${xmlEscape(new URL(path, origin).href)}</loc>${
      lastmod ? `<lastmod>${lastmod}</lastmod>` : ""
    }</url>`;
  const pages = items
    .slice(0, 100)
    .filter((i) => CANONICAL_PATH_PATTERN.test(i.canonical_path))
    .map((i) => url(i.canonical_path, isoDay(i.visible_from) || undefined));
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    url("/exploited"),
    ...pages,
    "</urlset>",
    "",
  ].join("\n");
}
