/**
 * EXAMPLE DATA for the public exploit pages (#35). Shapes match
 * schemas/public-exploit-list.schema.json and
 * schemas/public-exploit-page.schema.json. Not real telemetry: CVE ids are fake,
 * IPs come from RFC 5737 and products are invented.
 */
import type { PublicExploitList, PublicExploitPage } from "../lib/public-types";

const DAY = 86_400_000;
/** 2026-10-01T00:00:00Z. */
const OCT_1 = Date.UTC(2026, 9, 1);

export const examplePage: PublicExploitPage = {
  slug: "examplevpn-path-traversal",
  canonical_path: "/exploited/examplevpn-path-traversal",
  title: "ExampleVPN path traversal attempts (example data)",
  summary:
    "Example data. Attempts we assess as targeting CVE-2099-0001 in ExampleVPN, seen on Foiled sensors before the advisory.",
  body: [
    { type: "heading", level: 2, inlines: [{ type: "text", text: "What we saw" }] },
    {
      type: "paragraph",
      inlines: [
        { type: "text", text: "Requests to " },
        { type: "code", text: "/example/../../etc/passwd" },
        { type: "text", text: " from " },
        { type: "strong", text: "several sources" },
        { type: "text", text: ". See the " },
        { type: "link", text: "example advisory", href: "https://example.com/advisory" },
        { type: "text", text: " and our " },
        { type: "link", text: "exploit list", href: "/exploited" },
        { type: "text", text: "." },
      ],
    },
    {
      type: "list",
      ordered: false,
      items: [
        [{ type: "text", text: "First seen on a sensor in 203.0.113.0/24 space." }],
        [{ type: "emphasis", text: "Example data only." }],
      ],
    },
    { type: "quote", inlines: [{ type: "text", text: "Assessed, not guessed." }] },
    { type: "code", text: "GET /example/..%2f..%2fetc/passwd HTTP/1.1" },
    { type: "rule" },
    { type: "heading", level: 3, inlines: [{ type: "text", text: "Detection" }] },
  ],
  tlp: "clear",
  published_at: OCT_1 + 10 * DAY,
  visible_from: OCT_1 + 10 * DAY,
  version: 1,
  cves: [
    {
      id: "CVE-2099-0001",
      wording: "confirmed",
      confirmed_at: OCT_1 + 8 * DAY,
      advisory_published_at: OCT_1 + 5 * DAY,
    },
    {
      id: "FOILED-DEMO-0001",
      wording: "we assess as",
      confirmed_at: null,
      advisory_published_at: null,
    },
  ],
  techniques: [
    { id: "T1190", wording: "we assess as", confirmed_at: null, advisory_published_at: null },
  ],
  timeline: [
    { at: OCT_1 + 2 * DAY, kind: "first_seen", label: "First seen on Foiled sensors" },
    { at: OCT_1 + 5 * DAY, kind: "advisory_published", label: "Vendor advisory published" },
    { at: OCT_1 + 8 * DAY, kind: "confirmed", label: "Analyst confirmed CVE-2099-0001" },
    { at: OCT_1 + 10 * DAY, kind: "published", label: "Write-up published" },
  ],
  redacted_payload: "GET /example/..%2f..%2fetc/passwd HTTP/1.1\nHost: [masked]\nCookie: [masked]",
  iocs: [
    {
      type: "ipv4",
      display: "192.0.2[.]10",
      first_seen_day: OCT_1 + 2 * DAY,
      release_at: OCT_1 + 9 * DAY,
      tlp: "clear",
    },
    {
      type: "url",
      display: "hxxps://example[.]com/payload",
      first_seen_day: OCT_1 + 3 * DAY,
      release_at: OCT_1 + 9 * DAY,
      tlp: "clear",
    },
  ],
};

export const exampleList: PublicExploitList = {
  items: [
    {
      slug: examplePage.slug,
      canonical_path: examplePage.canonical_path,
      title: examplePage.title,
      summary: examplePage.summary,
      visible_from: examplePage.visible_from,
      cves: examplePage.cves,
    },
    {
      slug: "example-loader-campaign",
      canonical_path: "/exploited/example-loader-campaign",
      title: "Example-Loader delivery attempts (example data)",
      summary: "Example data. Attempts we assess as linked to FOILED-DEMO-0002.",
      visible_from: OCT_1 + 4 * DAY,
      cves: [
        {
          id: "FOILED-DEMO-0002",
          wording: "we assess as",
          confirmed_at: null,
          advisory_published_at: null,
        },
      ],
    },
  ],
};
