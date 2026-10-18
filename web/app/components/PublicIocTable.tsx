import { middleEllipsis, toPrintable } from "../lib/printable";
import { formatDay, isoDay } from "../lib/public-format";
import type { PublicIoc } from "../lib/public-types";

/**
 * Released IOCs on a public page: type, defanged value and first seen day.
 * Values arrive defanged and are shown as text only, never parsed or linked.
 */
export function PublicIocTable({ rows, caption }: { rows: readonly PublicIoc[]; caption: string }) {
  return (
    <table className="data-table iocs">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr>
          <th scope="col">Type</th>
          <th scope="col">Value (defanged)</th>
          <th scope="col">First seen (UTC)</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const value = toPrintable(String(r.display ?? ""));
          return (
            <tr key={`${r.type}-${r.display}`}>
              <td>
                <span className="tag">{toPrintable(String(r.type ?? ""))}</span>
              </td>
              <td className="mono">
                {value.length > 48 ? (
                  <details className="ioc-value">
                    <summary>{middleEllipsis(value, 48)}</summary>
                    <span className="ioc-value__full">{value}</span>
                  </details>
                ) : (
                  value
                )}
              </td>
              <td className="mono muted">
                <time dateTime={isoDay(r.first_seen_day)}>{formatDay(r.first_seen_day)}</time>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
