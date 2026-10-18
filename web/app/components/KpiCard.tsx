import type { ReactNode } from "react";
import { Change, type ChangeDirection } from "./Change";
import { Icon, type IconName } from "./icons";
import { Sparkline } from "./Sparkline";

export interface KpiCardProps {
  label: string;
  /** Preformatted value, for example "48,317". */
  value: string;
  icon?: IconName;
  /** Period-on-period change. Up is red (more attacks), down is green. */
  change?: { direction: ChangeDirection; pct: number };
  /** Short green note in place of a change, for example "14 warm". */
  note?: ReactNode;
  /** Series for the sparkline, oldest first. */
  series?: readonly number[];
  /** Show the value in red-bright, used for the headline attack count. */
  accent?: boolean;
}

export function KpiCard({
  label,
  value,
  icon,
  change,
  note,
  series,
  accent = false,
}: KpiCardProps) {
  return (
    <section className="card kpi" aria-label={label}>
      <h2 className="kpi__label">{label}</h2>
      <div className="kpi__row">
        {icon ? (
          <span className="kpi__icon">
            <Icon name={icon} size={24} />
          </span>
        ) : null}
        <span className={accent ? "kpi__value kpi__value--accent" : "kpi__value"}>{value}</span>
        {change ? <Change direction={change.direction} pct={change.pct} /> : null}
        {note ? <span className="kpi__note">{note}</span> : null}
      </div>
      {series && series.length > 1 ? (
        <Sparkline className="kpi__spark" values={series} width={120} height={40} />
      ) : null}
    </section>
  );
}
