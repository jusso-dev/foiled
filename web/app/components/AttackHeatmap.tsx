export interface HeatmapTechnique {
  /** ATT&CK technique id, for example "T1190". */
  id: string;
  name: string;
  /** One count per column, same order as `columns`. */
  counts: readonly number[];
}

export interface AttackHeatmapProps {
  caption: string;
  /** Column labels, for example time buckets or sensors. */
  columns: readonly string[];
  techniques: readonly HeatmapTechnique[];
}

/** Five steps from empty to full red. Index 0 is "no attempts". */
export function heatLevel(count: number, max: number): 0 | 1 | 2 | 3 | 4 {
  if (count <= 0 || max <= 0) return 0;
  return Math.min(4, Math.max(1, Math.ceil((count / max) * 4))) as 1 | 2 | 3 | 4;
}

/** ATT&CK technique ids by column, cell shade by count. A real table for screen readers. */
export function AttackHeatmap({ caption, columns, techniques }: AttackHeatmapProps) {
  const max = Math.max(0, ...techniques.flatMap((t) => t.counts));
  return (
    <div className="heatmap-wrap">
      <table className="heatmap">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Technique</th>
            {columns.map((c) => (
              <th scope="col" key={c} className="heatmap__col">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {techniques.map((t) => (
            <tr key={t.id}>
              <th scope="row" className="heatmap__row">
                <span className="mono heatmap__id">{t.id}</span>
                <span className="heatmap__name">{t.name}</span>
              </th>
              {columns.map((c, i) => {
                const n = t.counts[i] ?? 0;
                return (
                  <td
                    key={c}
                    className={`heatmap__cell heat-${heatLevel(n, max)}`}
                    title={`${t.id} ${t.name}, ${c}: ${n} attempts`}
                  >
                    <span className="mono">{n || ""}</span>
                    {n ? null : <span className="sr-only">0</span>}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="heatmap__legend" aria-hidden="true">
        <span>fewer</span>
        {[1, 2, 3, 4].map((l) => (
          <span key={l} className={`heatmap__swatch heat-${l}`} />
        ))}
        <span>more</span>
      </p>
    </div>
  );
}
