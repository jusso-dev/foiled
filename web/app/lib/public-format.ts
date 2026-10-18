/**
 * Formatting and link rules for the public pages (#35). Pure functions so
 * the rules are tested without rendering.
 */

const DAY_FORMAT = new Intl.DateTimeFormat("en-AU", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

/** Unix ms as `18 Oct 2026` in UTC. Empty for a value that is not a date. */
export function formatDay(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : DAY_FORMAT.format(d);
}

/** Unix ms as an ISO date (`2026-10-18`) for `<time dateTime>` and the sitemap. */
export function isoDay(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

const SAFE_BASE = "https://foiled.invalid";

/**
 * A link target that is safe to put in `href`, or null to drop the link.
 * Allowed: `https://` URLs and site-relative paths starting with a single
 * `/`. The API already enforces this; we check again because the page is
 * public and the text came from a write-up. Resolving with URL catches
 * `/\host`, which browsers treat as `//host`.
 */
export function safeHref(href: unknown): string | null {
  if (typeof href !== "string" || href.length === 0 || href.length > 2048) return null;
  // Whitespace, control characters and backslashes have no place in a link.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point.
  if (/[\u0000- \u007f-\u009f\\]/.test(href)) return null;
  if (href.startsWith("https://")) {
    try {
      const u = new URL(href);
      if (u.protocol !== "https:" || u.username || u.password || !u.hostname) return null;
      return u.href;
    } catch {
      return null;
    }
  }
  if (href.startsWith("/") && !href.startsWith("//")) {
    try {
      const u = new URL(href, SAFE_BASE);
      if (u.origin !== SAFE_BASE) return null;
      return `${u.pathname}${u.search}${u.hash}`;
    } catch {
      return null;
    }
  }
  return null;
}

/** True for an absolute link that leaves the site. */
export function isExternalHref(href: string): boolean {
  return href.startsWith("https://");
}

/** Rel for links to other sites from user-written text. */
export const EXTERNAL_REL = "nofollow noopener noreferrer ugc";
