import { useId } from "react";
import { Form, Link } from "react-router";
import { ConfidenceChip } from "../components/ConfidenceChip";
import { PageHead, Time } from "../components/console/Controls";
import { EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { windowQuery } from "../components/console/Tables";
import type { CampaignStatus } from "../lib/api-types";
import { field, intField, load, oneOf, requireOperator, windowFrom } from "../lib/console.server";
import { campaignSentence, confidenceOf } from "../lib/links";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/campaigns";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Campaigns · Foiled console" }];
}

const STATUSES: readonly CampaignStatus[] = ["emerging", "active", "closed"];

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const w = windowFrom(params);
  const filters = {
    window: w.key ?? "",
    status: oneOf(params, "status", STATUSES) ?? "",
    cve: field(params, "cve", 64) ?? "",
    min_confidence: intField(params, "min_confidence", 0, 100) ?? "",
  };
  const res = await load(
    args.request,
    op.api.listCampaigns({
      since: w.since,
      until: w.until,
      ...filters,
      window: undefined,
      limit: 100,
    }),
  );
  return {
    filters,
    window: { since: w.since, until: w.until },
    campaigns: res.ok ? res.data.items : [],
    notes: res.ok ? res.data.notes : [],
    truncated: res.ok ? res.data.truncated : false,
    error: res.ok ? null : res.error,
  };
}

export default function Campaigns({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  const wq = windowQuery(d.window);
  return (
    <>
      <PageHead title="Campaigns">
        <span className="muted">
          Attempts that may share an operator. Worded "possible" until an analyst confirms.
        </span>
      </PageHead>
      <section className="card panel" aria-label="Campaigns">
        <Form method="get" className="filters" aria-label="Filter campaigns">
          <div className="field">
            <label htmlFor={`${id}-window`}>Window</label>
            <select id={`${id}-window`} name="window" defaultValue={d.filters.window || "7d"}>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="31d">Last 31 days (the maximum)</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-status`}>Status</label>
            <select id={`${id}-status`} name="status" defaultValue={d.filters.status}>
              <option value="">Any</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-cve`}>CVE</label>
            <input id={`${id}-cve`} name="cve" defaultValue={d.filters.cve} maxLength={64} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-min`}>Minimum confidence</label>
            <input
              id={`${id}-min`}
              name="min_confidence"
              type="number"
              min={0}
              max={100}
              defaultValue={d.filters.min_confidence}
            />
          </div>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.truncated ? (
          <Notice kind="warn">
            <p>The window held more events than one read covers. Narrow it to see everything.</p>
          </Notice>
        ) : null}
        {d.notes.length ? (
          <Notice kind="info">
            {d.notes.map((n) => (
              <p key={n}>{toPrintable(n)}</p>
            ))}
          </Notice>
        ) : null}
        {d.error ? <ErrorState what="Campaigns" error={d.error} /> : null}
        {!d.error && d.campaigns.length === 0 ? (
          <EmptyState>
            <p>
              No campaigns in this window. Campaigns need at least two attempts that share a
              feature.
            </p>
          </EmptyState>
        ) : null}
        {d.campaigns.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">Campaigns, newest activity first</caption>
              <thead>
                <tr>
                  <th scope="col">Campaign</th>
                  <th scope="col">Status</th>
                  <th scope="col">Targeting</th>
                  <th scope="col" className="num">
                    Attempts
                  </th>
                  <th scope="col">Last seen</th>
                  <th scope="col">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {d.campaigns.map((c) => {
                  const conf = confidenceOf(c.confidence);
                  return (
                    <tr key={c.campaign_id}>
                      <td className="wrap">
                        <Link className="link" to={`/campaigns/${c.campaign_id}${wq}`}>
                          {toPrintable(c.title)}
                        </Link>
                        <div className="mono muted">{c.campaign_id}</div>
                      </td>
                      <td>
                        <span className="tag">{c.status}</span>
                      </td>
                      <td>{c.feature_summary.targeting.pattern}</td>
                      <td className="num mono">{c.attempt_ids.length}</td>
                      <td className="mono muted">
                        <Time ms={c.last_seen} />
                      </td>
                      <td>
                        <ConfidenceChip
                          level={conf.level}
                          score={conf.score}
                          wording={campaignSentence(c.confidence.score, c.confidence.wording)}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Campaigns" />;
}
