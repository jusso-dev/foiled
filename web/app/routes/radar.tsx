import { useId } from "react";
import { Form, Link } from "react-router";
import { Change } from "../components/Change";
import { PageHead, Time } from "../components/console/Controls";
import { EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { Sparkline } from "../components/Sparkline";
import type { RadarDimension, RadarSeries } from "../lib/api-types";
import { intField, load, oneOf, requireOperator } from "../lib/console.server";
import { formatCount } from "../lib/format";
import { isId } from "../lib/ids";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/radar";

// TODO(#35): /v0/radar is not on main yet. This is the trusted-side operator
// radar from PR #84 (docs/radar.md there); there is no public radar.

export function meta(_: Route.MetaArgs) {
  return [{ title: "Radar · Foiled console" }];
}

const DIMENSIONS: readonly RadarDimension[] = ["cve", "technique", "campaign", "product"];
const DIMENSION_LABEL: Record<RadarDimension, string> = {
  cve: "CVEs",
  technique: "ATT&CK techniques",
  campaign: "Campaigns",
  product: "Targeted products",
};
const DAYS = [7, 30, 92] as const;

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const p = new URL(args.request.url).searchParams;
  const audience = oneOf(p, "audience", ["tenant", "fleet"] as const) ?? "tenant";
  const dimension = oneOf(p, "dimension", DIMENSIONS) ?? "";
  const days = intField(p, "days", 1, 92) ?? 30;
  const since = Date.now() - days * 24 * 3600_000;
  const res = await load(args.request, op.api.getRadar({ audience, dimension, since, limit: 20 }));
  return {
    filters: { audience, dimension, days },
    feed: res.ok ? res.data : null,
    error: res.ok ? null : res.error,
  };
}

/** Where a series key leads in the console, when it is one of our ids. */
function seriesHref(s: RadarSeries): string | null {
  if (s.dimension === "cve") return `/attempts?cve=${encodeURIComponent(s.key)}`;
  if (s.dimension === "technique") return `/attempts?technique=${encodeURIComponent(s.key)}`;
  if (s.dimension === "campaign" && isId("campaign", s.key)) return `/campaigns/${s.key}`;
  return null;
}

const WORDING: Record<RadarSeries["wording"], string> = {
  "we assess as": "We assess as",
  possible: "Possible",
  observed: "Observed",
};

export default function Radar({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  const f = d.feed;
  const byDim = DIMENSIONS.map(
    (dim) => [dim, f?.series.filter((s) => s.dimension === dim) ?? []] as const,
  ).filter(([, s]) => s.length);
  return (
    <>
      <PageHead title="Radar">
        <span className="muted">Counts and trends from closed days. Trusted side only.</span>
      </PageHead>
      <section className="card panel" aria-label="Radar settings">
        <Form method="get" className="filters" aria-label="Radar settings">
          <fieldset className="fieldset fieldset--inline">
            <legend>Audience</legend>
            <label className="radio">
              <input
                type="radio"
                name="audience"
                value="tenant"
                defaultChecked={d.filters.audience === "tenant"}
              />{" "}
              My tenant
            </label>
            <label className="radio">
              <input
                type="radio"
                name="audience"
                value="fleet"
                defaultChecked={d.filters.audience === "fleet"}
              />{" "}
              Fleet (opted-in sensors, thresholds applied)
            </label>
          </fieldset>
          <div className="field">
            <label htmlFor={`${id}-dim`}>Dimension</label>
            <select id={`${id}-dim`} name="dimension" defaultValue={d.filters.dimension}>
              <option value="">All</option>
              {DIMENSIONS.map((x) => (
                <option key={x} value={x}>
                  {DIMENSION_LABEL[x]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-days`}>Window</label>
            <select id={`${id}-days`} name="days" defaultValue={String(d.filters.days)}>
              {DAYS.map((n) => (
                <option key={n} value={n}>
                  Last {n} days{n === 92 ? " (the maximum)" : ""}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.error ? <ErrorState what="Radar" error={d.error} issue={35} /> : null}
      </section>
      {f ? (
        <>
          <Notice kind="info" title="What counts">
            <p>
              {f.audience === "fleet"
                ? `Fleet counts need at least ${f.policy.min_sources} sources, ${f.policy.min_sensors} sensors and ${f.policy.min_edge_tenants} edge tenants per bucket; no tenant is named.`
                : "Your tenant's own data."}{" "}
              Links below {f.policy.min_confidence} confidence never count; headlines use
              publishable counts only. Days shown: <Time ms={f.since} /> to <Time ms={f.until} />
              {f.policy.delay_days ? `, held back ${f.policy.delay_days} days` : ""}.
              {f.suppressed_buckets
                ? ` ${f.suppressed_buckets} buckets held back by the thresholds.`
                : ""}
            </p>
            {f.notes.map((n) => (
              <p key={n}>{toPrintable(n)}</p>
            ))}
          </Notice>
          <section className="card panel" aria-label="Headlines">
            <header className="panel__head">
              <h2 className="panel__title">Headlines</h2>
            </header>
            {f.cards.length ? (
              <ul className="bullets panel__body">
                {f.cards.map((c) => (
                  <li key={c.card_id}>
                    <Time ms={c.day} /> {toPrintable(c.headline)}{" "}
                    <span className="muted">
                      ({formatCount(c.attempts)} attempts, {formatCount(c.sources)} sources)
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState>
                <p>No headlines in this window.</p>
              </EmptyState>
            )}
          </section>
          {byDim.length === 0 ? (
            <EmptyState>
              <p>No counts yet. Radar rolls up closed days; check back tomorrow.</p>
            </EmptyState>
          ) : null}
          {byDim.map(([dim, series]) => (
            <section key={dim} className="card panel" aria-label={DIMENSION_LABEL[dim]}>
              <header className="panel__head">
                <h2 className="panel__title">{DIMENSION_LABEL[dim]}</h2>
              </header>
              <div className="table-wrap">
                <table className="data-table">
                  <caption className="sr-only">{DIMENSION_LABEL[dim]} by attempts</caption>
                  <thead>
                    <tr>
                      <th scope="col">Series</th>
                      <th scope="col">Wording</th>
                      <th scope="col">Best band</th>
                      <th scope="col" className="num">
                        Attempts
                      </th>
                      <th scope="col" className="num">
                        Sources
                      </th>
                      <th scope="col">Trend</th>
                      <th scope="col">Daily</th>
                    </tr>
                  </thead>
                  <tbody>
                    {series.map((s) => {
                      const href = seriesHref(s);
                      const label = toPrintable(s.label);
                      return (
                        <tr key={`${s.dimension}-${s.key}`}>
                          <td className="wrap">
                            {href ? (
                              <Link className="link" to={href}>
                                {label}
                              </Link>
                            ) : (
                              label
                            )}
                          </td>
                          <td>{WORDING[s.wording] ?? "We assess as"}</td>
                          <td>{s.best_band}</td>
                          <td className="num mono">{formatCount(s.total_attempts)}</td>
                          <td className="num mono">{formatCount(s.total_sources)}</td>
                          <td>
                            <Change direction={s.trend.direction} pct={s.trend.pct} />
                          </td>
                          <td>
                            {s.days.length > 1 ? (
                              <Sparkline
                                values={s.days.map((x) => x.attempts)}
                                width={96}
                                height={24}
                              />
                            ) : null}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
        </>
      ) : null}
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Radar" />;
}
