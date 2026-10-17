import type { Confidence } from "../lib/confidence";
import { middleEllipsis, toPrintable } from "../lib/printable";
import { ConfidenceChip } from "./ConfidenceChip";

export type IocType = "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "user-agent";

export interface IocRow {
  key: string;
  type: IocType;
  /** Attacker-derived value. Rendered as text only. */
  value: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
  confidence?: Confidence;
}

const TYPE_LABEL: Record<IocType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  sha256: "SHA-256",
  "user-agent": "User agent",
};

/** Indicators of compromise. Long values are shortened in the middle; the full value is in the tooltip. */
export function IocTable({ rows, caption }: { rows: readonly IocRow[]; caption: string }) {
  return (
    <table className="data-table iocs">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr>
          <th scope="col">Type</th>
          <th scope="col">Value</th>
          <th scope="col">First seen</th>
          <th scope="col">Last seen</th>
          <th scope="col" className="num">
            Count
          </th>
          <th scope="col">Confidence</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const safe = toPrintable(r.value);
          return (
            <tr key={r.key}>
              <td>
                <span className="tag">{TYPE_LABEL[r.type]}</span>
              </td>
              <td className="mono" title={safe}>
                {middleEllipsis(safe, 40)}
              </td>
              <td className="mono muted">{r.firstSeen}</td>
              <td className="mono muted">{r.lastSeen}</td>
              <td className="mono num">{r.count.toLocaleString("en-AU")}</td>
              <td>
                {r.confidence ? (
                  <ConfidenceChip level={r.confidence.level} score={r.confidence.score} />
                ) : (
                  <span className="muted">n/a</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
