import {
  CONFIDENCE_LABEL,
  type ConfidenceLevel,
  clampScore,
  confidenceWording,
} from "../lib/confidence";

export interface EvidenceEntry {
  id: string;
  /** What was observed, in plain words. */
  signal: string;
  /** Where it came from, for example "vulnerable-path hook" or "payload match". */
  source: string;
  /** Points this entry added to (positive) or removed from (negative) the score. */
  points: number;
  /** Offset or time label, for example "+0.412s". */
  at?: string;
}

export interface ConfidenceMeterProps {
  level: ConfidenceLevel;
  score: number;
  /** What the confidence is about, usually a CVE id. */
  subject: string;
  evidence: readonly EvidenceEntry[];
  /** Full sentence when the link is not a CVE (lib/links.ts). Defaults to the CVE wording. */
  wording?: string;
  /** Heading level for the "Confidence" title, so the meter fits the page outline. */
  headingLevel?: 2 | 3;
}

/**
 * Score bar coloured by level, with the evidence ledger that produced it.
 * The ledger lists contributions as recorded; it does not recompute the score.
 */
export function ConfidenceMeter({
  level,
  score,
  subject,
  evidence,
  wording,
  headingLevel = 2,
}: ConfidenceMeterProps) {
  const s = clampScore(score);
  const Heading = headingLevel === 3 ? "h3" : "h2";
  return (
    <section className={`card meter meter--${level}`} aria-label={`Confidence for ${subject}`}>
      <header className="meter__head">
        <Heading className="panel__title">Confidence</Heading>
        <span className="meter__score mono">
          {CONFIDENCE_LABEL[level]} {s}
        </span>
      </header>
      <p className="meter__wording">{wording ?? confidenceWording(level, s, subject)}</p>
      {/* Native meter for assistive tech; the styled bar below is decorative. */}
      <meter
        className="sr-only"
        min={0}
        max={100}
        value={s}
        aria-label={`Confidence score for ${subject}: ${CONFIDENCE_LABEL[level]} ${s} of 100`}
      />
      <div className="meter__track" aria-hidden="true">
        <span className="meter__fill" style={{ width: `${s}%` }} />
      </div>
      <table className="data-table ledger">
        <caption className="sr-only">Evidence ledger for {subject}</caption>
        <thead>
          <tr>
            <th scope="col">At</th>
            <th scope="col">Signal</th>
            <th scope="col">Source</th>
            <th scope="col" className="num">
              Points
            </th>
          </tr>
        </thead>
        <tbody>
          {evidence.map((e) => (
            <tr key={e.id}>
              <td className="mono muted">{e.at ?? ""}</td>
              <td className="wrap">{e.signal}</td>
              <td className="muted">{e.source}</td>
              <td className={e.points >= 0 ? "num mono pts-up" : "num mono pts-down"}>
                {e.points >= 0 ? `+${e.points}` : `−${Math.abs(e.points)}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
