import { Change, type ChangeDirection } from "./Change";
import { Sparkline } from "./Sparkline";

export interface TrendRow {
  key: string;
  label: string;
  /** One or two character badge before the label, for example a country code. */
  badge?: string;
  value: number;
  change?: { direction: ChangeDirection; pct: number };
  series: readonly number[];
}

export interface TrendTableProps {
  caption: string;
  rows: readonly TrendRow[];
  labelHeader: string;
  valueHeader: string;
  /** Show the change column. */
  showChange?: boolean;
  /** Round badge (malware) or square code chip (countries). */
  badgeStyle?: "round" | "square";
  sparkWidth?: number;
}

/** Name, count, change arrow and a sparkline per row. */
export function TrendTable({
  caption,
  rows,
  labelHeader,
  valueHeader,
  showChange = true,
  badgeStyle = "round",
  sparkWidth = 92,
}: TrendTableProps) {
  return (
    <table className="data-table trend">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr>
          <th scope="col">{labelHeader}</th>
          <th scope="col">{valueHeader}</th>
          {showChange ? <th scope="col">Change</th> : null}
          <th scope="col">Trend</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key}>
            <td>
              {r.badge ? (
                <span className={badgeStyle === "round" ? "badge-round" : "tag tag--lead"}>
                  {r.badge}
                </span>
              ) : null}
              {r.label}
            </td>
            <td className="mono">{r.value.toLocaleString("en-AU")}</td>
            {showChange ? (
              <td>
                {r.change ? <Change direction={r.change.direction} pct={r.change.pct} /> : null}
              </td>
            ) : null}
            <td>
              <Sparkline values={r.series} width={sparkWidth} height={18} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
