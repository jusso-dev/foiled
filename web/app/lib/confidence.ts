/**
 * Confidence levels shown in the UI. Wording follows docs/ui/voice.md and the
 * glossary: "we assess as" until an analyst confirms, "confirmed" only after.
 */
export type ConfidenceLevel = "assessed" | "probable" | "confirmed";

export interface Confidence {
  level: ConfidenceLevel;
  /** Score from 0 to 100. */
  score: number;
}

export const CONFIDENCE_LABEL: Record<ConfidenceLevel, string> = {
  assessed: "Assessed",
  probable: "Probable",
  confirmed: "Confirmed",
};

export function clampScore(score: number): number {
  if (!Number.isFinite(score)) return 0;
  return Math.min(100, Math.max(0, Math.round(score)));
}

/**
 * Full sentence for a confidence level, used for screen readers and tooltips.
 * `subject` is what the link points at, usually a CVE id.
 */
export function confidenceWording(level: ConfidenceLevel, score: number, subject?: string): string {
  const s = clampScore(score);
  switch (level) {
    case "assessed":
      return `We assess as ${subject ? `an attempt against ${subject}` : "linked"}. Score ${s} of 100, not confirmed by an analyst.`;
    case "probable":
      return `Probable${subject ? ` attempt against ${subject}` : ""}. Score ${s} of 100, not yet confirmed by an analyst.`;
    case "confirmed":
      return `Confirmed by an analyst${subject ? ` as an attempt against ${subject}` : ""}. Score ${s} of 100.`;
  }
}

/** The parts of an API confidence link (#27, `schemas/confidence-link.schema.json`) the chip needs. */
export interface ApiLink {
  score: number;
  band: "low" | "medium" | "high";
  wording: "we assess as" | "confirmed";
}

/**
 * Chip level for an API link. Only an analyst confirmation shows as
 * Confirmed; an unconfirmed `high` link is Probable; everything else is
 * Assessed. The score is passed through unchanged.
 */
export function confidenceFromLink(link: ApiLink): Confidence {
  const level: ConfidenceLevel =
    link.wording === "confirmed" ? "confirmed" : link.band === "high" ? "probable" : "assessed";
  return { level, score: clampScore(link.score) };
}
