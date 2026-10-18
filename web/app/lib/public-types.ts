/**
 * Types for the public API (#35). They mirror
 * schemas/public-exploit-list.schema.json and
 * schemas/public-exploit-page.schema.json. Kept apart from public-api.server.ts so
 * components can import them. Every string here is attacker-influenced:
 * render with toPrintable.
 */

/** Slug and canonical path patterns from the schemas. */
export const SLUG_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;
export const CANONICAL_PATH_PATTERN = /^\/exploited\/[a-z0-9]+(-[a-z0-9]+)*$/;

export type PublicWording = "we assess as" | "confirmed";

export interface PublicAssessment {
  id: string;
  wording: PublicWording;
  confirmed_at: number | null;
  advisory_published_at: number | null;
}

export interface PublicExploitListItem {
  slug: string;
  canonical_path: string;
  title: string;
  summary: string;
  visible_from: number;
  cves: PublicAssessment[];
}

export interface PublicExploitList {
  items: PublicExploitListItem[];
}

export type InlineNode =
  | { type: "text" | "strong" | "emphasis" | "code"; text: string }
  | { type: "link"; text: string; href: string };

export type BlockNode =
  | { type: "heading"; level: number; inlines: InlineNode[] }
  | { type: "paragraph" | "quote"; inlines: InlineNode[] }
  | { type: "list"; ordered: boolean; items: InlineNode[][] }
  | { type: "code"; text: string }
  | { type: "rule" };

export type TimelineKind = "first_seen" | "advisory_published" | "confirmed" | "published";

export interface PublicTimelineEntry {
  at: number;
  kind: TimelineKind;
  label: string;
}

export interface PublicIoc {
  type: string;
  /** Defanged. Never parse it. */
  display: string;
  first_seen_day: number;
  release_at: number;
  tlp: "clear";
}

export interface PublicExploitPage {
  slug: string;
  canonical_path: string;
  title: string;
  summary: string;
  body: BlockNode[];
  tlp: "clear";
  published_at: number;
  visible_from: number;
  version: number;
  cves: PublicAssessment[];
  techniques: PublicAssessment[];
  timeline: PublicTimelineEntry[];
  redacted_payload: string | null;
  iocs: PublicIoc[];
}
