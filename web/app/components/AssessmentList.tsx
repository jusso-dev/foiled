import { toPrintable } from "../lib/printable";
import { formatDay } from "../lib/public-format";
import type { PublicAssessment } from "../lib/public-types";
import { CveRef } from "./CveRef";
import { WordingChip } from "./WordingChip";

/**
 * CVEs and ATT&CK techniques linked to a public write-up, each with its
 * wording: "We assess as" until an analyst confirms, "Confirmed" after.
 */
export function AssessmentList({
  cves,
  techniques,
}: {
  cves: readonly PublicAssessment[];
  techniques: readonly PublicAssessment[];
}) {
  return (
    <ul className="pub-assess">
      {cves.map((c) => (
        <li key={`cve-${c.id}`}>
          <CveRef id={c.id} wording={c.wording} />
          <Dates item={c} />
        </li>
      ))}
      {techniques.map((t) => {
        const id = toPrintable(t.id);
        return (
          <li key={`ttp-${t.id}`}>
            <span className="tag">{id}</span>
            <WordingChip wording={t.wording} what={`technique ${id}`} />
            <Dates item={t} />
          </li>
        );
      })}
    </ul>
  );
}

function Dates({ item }: { item: PublicAssessment }) {
  const parts: string[] = [];
  if (typeof item.advisory_published_at === "number") {
    parts.push(`Advisory ${formatDay(item.advisory_published_at)}`);
  }
  // A confirmation date only means something next to the confirmed wording.
  if (item.wording === "confirmed" && typeof item.confirmed_at === "number") {
    parts.push(`confirmed ${formatDay(item.confirmed_at)}`);
  }
  return parts.length > 0 ? (
    <span className="muted pub-assess__dates">{parts.join(", ")}</span>
  ) : null;
}
