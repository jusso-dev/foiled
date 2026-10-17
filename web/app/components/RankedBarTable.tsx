export interface RankedBarRow {
  key: string;
  label: string;
  /** Small grey code chip before or after the label, for example a country code. */
  tag?: string;
  value: number;
}

export interface RankedBarTableProps {
  caption: string;
  rows: readonly RankedBarRow[];
  labelHeader: string;
  valueHeader: string;
  /** Optional header for the tag column. Tags render in their own column when set. */
  tagHeader?: string;
  /** `count` shows bars only (value in the accessible text); `percent` adds a red % label. */
  format?: "count" | "percent";
  /** Use the mono face for labels (IPs, hashes). */
  monoLabel?: boolean;
}

/** Top-N table with a dark-to-red bar per row, scaled to the largest value. */
export function RankedBarTable({
  caption,
  rows,
  labelHeader,
  valueHeader,
  tagHeader,
  format = "count",
  monoLabel = false,
}: RankedBarTableProps) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <table className="data-table ranked">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr>
          <th scope="col">{labelHeader}</th>
          {tagHeader ? <th scope="col">{tagHeader}</th> : null}
          <th scope="col">{valueHeader}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const pct = Math.round((r.value / max) * 100);
          const text = format === "percent" ? `${r.value}%` : r.value.toLocaleString("en-AU");
          return (
            <tr key={r.key}>
              <td className={monoLabel ? "mono" : undefined}>
                {!tagHeader && r.tag ? <span className="tag tag--lead">{r.tag}</span> : null}
                {r.label}
              </td>
              {tagHeader ? <td>{r.tag ? <span className="tag">{r.tag}</span> : null}</td> : null}
              <td>
                <div className="bar-cell">
                  <span className="bar" style={{ width: `${pct}%` }} aria-hidden="true" />
                  {format === "percent" ? (
                    <span className="bar-cell__pct">{text}</span>
                  ) : (
                    <span className="sr-only">{text}</span>
                  )}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
