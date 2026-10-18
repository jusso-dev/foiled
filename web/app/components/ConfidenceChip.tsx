import {
  CONFIDENCE_LABEL,
  type ConfidenceLevel,
  clampScore,
  confidenceWording,
} from "../lib/confidence";

export interface ConfidenceChipProps {
  level: ConfidenceLevel;
  /** Score from 0 to 100, shown on the chip. */
  score: number;
  /** What the confidence is about, usually a CVE id. Used in the full wording. */
  subject?: string;
}

/**
 * `ASSESSED 64` (amber), `PROBABLE 81` (blue), `CONFIRMED 96` (green).
 * The visible chip is short; the full sentence ("We assess as ...") is in the
 * tooltip and read by screen readers.
 */
export function ConfidenceChip({ level, score, subject }: ConfidenceChipProps) {
  const wording = confidenceWording(level, score, subject);
  return (
    <span className={`chip chip--${level}`} title={wording} data-confidence={level}>
      <span className="sr-only">{wording}</span>
      <span aria-hidden="true">
        {CONFIDENCE_LABEL[level]} {clampScore(score)}
      </span>
    </span>
  );
}
