import type { Confidence } from "../lib/confidence";
import { toPrintable } from "../lib/printable";
import { ConfidenceChip } from "./ConfidenceChip";
import { WordingChip } from "./WordingChip";

interface CveRefBase {
  /** CVE id, for example `CVE-2099-EXAMPLE1`. */
  id: string;
  /**
   * `inline` (default) puts the chip next to the id. `column` leaves it out
   * because the same table row renders the chip in its Confidence column
   * (see ExploitTable). Confidence is still required either way.
   */
  chipPlacement?: "inline" | "column";
}

export type CveRefProps = CveRefBase &
  (
    | {
        /** Console: every CVE shown in the UI carries a confidence chip. */
        confidence: Confidence;
        wording?: never;
      }
    | {
        /** Public pages (#35): wording from the public API, no score. */
        wording: "we assess as" | "confirmed";
        confidence?: never;
      }
  );

/**
 * The only way to show a CVE id. A confidence (console) or wording (public)
 * prop is required by the type and checked at runtime, so a CVE never
 * renders without its "we assess as" context. A row that arrives without
 * either says so instead of taking the whole page down.
 */
export function CveRef({ id, confidence, wording, chipPlacement = "inline" }: CveRefProps) {
  const shown = toPrintable(id);
  if (wording !== undefined) {
    const level = wording === "confirmed" ? "confirmed" : "assessed";
    return (
      <span className="cve-ref" data-confidence={level}>
        <span className="cve-ref__id">{shown}</span>
        {chipPlacement === "inline" ? (
          <WordingChip wording={wording} what={`an attempt against ${shown}`} />
        ) : null}
      </span>
    );
  }
  if (!confidence || typeof confidence.score !== "number" || !confidence.level) {
    return (
      <span className="cve-ref" data-confidence="missing">
        <span className="cve-ref__id">{shown}</span>{" "}
        <span className="muted">(confidence missing, not assessed)</span>
      </span>
    );
  }
  return (
    <span className="cve-ref" data-confidence={confidence.level}>
      <span className="cve-ref__id">{shown}</span>
      {chipPlacement === "inline" ? (
        <ConfidenceChip level={confidence.level} score={confidence.score} subject={shown} />
      ) : null}
    </span>
  );
}
