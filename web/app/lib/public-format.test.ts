import { describe, expect, it } from "vitest";
import { formatDay, isoDay, safeHref } from "./public-format";

describe("formatDay", () => {
  it("formats in en-AU as dd MMM yyyy in UTC", () => {
    expect(formatDay(Date.UTC(2026, 9, 18, 23, 59))).toBe("18 Oct 2026");
    expect(formatDay(Date.UTC(2026, 0, 5))).toBe("05 Jan 2026");
    expect(isoDay(Date.UTC(2026, 9, 18))).toBe("2026-10-18");
  });

  it("returns an empty string for a value that is not a date", () => {
    expect(formatDay(Number.NaN)).toBe("");
    expect(isoDay(Number.POSITIVE_INFINITY)).toBe("");
  });
});

describe("safeHref", () => {
  it("keeps https and site-relative links", () => {
    expect(safeHref("https://example.com/a?b=1#c")).toBe("https://example.com/a?b=1#c");
    expect(safeHref("/exploited")).toBe("/exploited");
    expect(safeHref("/exploited/a-b?x=1")).toBe("/exploited/a-b?x=1");
  });

  it.each([
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    " javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "//evil.example/x",
    "/\\evil.example/x",
    "\\\\evil.example",
    "http://example.com",
    "https://user:pass@example.com/",
    "https://",
    "exploited",
    "#top",
    "",
    "/a\nb",
    "https://exa\tmple.com",
  ])("drops %s", (href) => {
    expect(safeHref(href)).toBeNull();
  });

  it("drops non-strings", () => {
    expect(safeHref(undefined)).toBeNull();
    expect(safeHref({ href: "/x" })).toBeNull();
  });
});
