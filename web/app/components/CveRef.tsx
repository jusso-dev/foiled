import type { Confidence } from "../lib/confidence";
import { ConfidenceChip } from "./ConfidenceChip";

export interface CveRefProps {
  /** CVE id, for example `CVE-2099-EXAMPLE1`. */
  id: string;
  /** Required: every CVE shown in the UI carries a confidence chip. */
  confidence: Confidence;
  /**
   * `inline` (default) puts the chip next to the id. `column` leaves it out
   * because the same table row renders the chip in its Confidence column
   * (see ExploitTable). Confidence is still required either way.
   */
  chipPlacement?: "inline" | "column";
}

/**
 * The only way to show a CVE id in the console. The `confidence` prop is
 * required by the type and checked at runtime, so a CVE never renders without
 * its "we assess as" context.
 */
export function CveRef({ id, confidence, chipPlacement = "inline" }: CveRefProps) {
  if (!confidence || typeof confidence.score !== "number" || !confidence.level) {
    throw new Error(`CveRef ${id}: a confidence level and score are required`);
  }
  return (
    <span className="cve-ref" data-confidence={confidence.level}>
      <span className="cve-ref__id">{id}</span>
      {chipPlacement === "inline" ? (
        <ConfidenceChip level={confidence.level} score={confidence.score} subject={id} />
      ) : null}
    </span>
  );
}
