import { useId } from "react";
import { Form } from "react-router";
import { PageHead } from "../components/console/Controls";
import { EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { AttemptsTable } from "../components/console/Tables";
import type { AttemptState, DecoyKind } from "../lib/api-types";
import {
  field,
  intField,
  load,
  oneOf,
  requireOperator,
  type WindowKey,
  windowFrom,
} from "../lib/console.server";
import { isId } from "../lib/ids";
import type { Route } from "./+types/attempts";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Attempts · Foiled console" }];
}

const STATES: readonly AttemptState[] = ["probe", "exploit", "post-exploitation"];
const KINDS: readonly DecoyKind[] = ["sandbox", "emulation"];
const WINDOW_LABEL: Record<WindowKey, string> = {
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "31d": "Last 31 days (the maximum)",
};

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const w = windowFrom(params);
  const technique = field(params, "technique", 16)?.toUpperCase();
  const filters = {
    window: w.key ?? "",
    state: oneOf(params, "state", STATES) ?? "",
    decoy_kind: oneOf(params, "decoy_kind", KINDS) ?? "",
    cve: field(params, "cve", 64) ?? "",
    technique: technique && /^T\d{4}(\.\d{3})?$/.test(technique) ? technique : "",
    src: field(params, "src", 64) ?? "",
    min_confidence: intField(params, "min_confidence", 0, 100) ?? "",
    decoy_id: isId("opaque", params.get("decoy_id")) ? String(params.get("decoy_id")) : "",
    campaign_id: isId("campaign", params.get("campaign_id"))
      ? String(params.get("campaign_id"))
      : "",
  };
  const res = await load(
    args.request,
    op.api.listAttempts({
      since: w.since,
      until: w.until,
      state: filters.state,
      decoy_kind: filters.decoy_kind,
      cve: filters.cve,
      technique: filters.technique,
      src: filters.src,
      min_confidence: filters.min_confidence,
      decoy_id: filters.decoy_id,
      campaign_id: filters.campaign_id,
      limit: 100,
    }),
  );
  return {
    filters,
    window: { since: w.since, until: w.until },
    attempts: res.ok ? res.data.items : [],
    truncated: res.ok ? res.data.truncated : false,
    error: res.ok ? null : res.error,
  };
}

export default function Attempts({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  const f = d.filters;
  return (
    <>
      <PageHead title="Attempts">
        <span className="muted">Exploit attempts grouped from capture events, newest first.</span>
      </PageHead>
      <section className="card panel" aria-label="Attempts">
        <Form method="get" className="filters" aria-label="Filter attempts">
          <div className="field">
            <label htmlFor={`${id}-window`}>Window</label>
            <select id={`${id}-window`} name="window" defaultValue={f.window || "7d"}>
              {Object.entries(WINDOW_LABEL).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-state`}>State</label>
            <select id={`${id}-state`} name="state" defaultValue={f.state}>
              <option value="">Any</option>
              {STATES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-kind`}>Decoy kind</label>
            <select id={`${id}-kind`} name="decoy_kind" defaultValue={f.decoy_kind}>
              <option value="">Any</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-cve`}>CVE</label>
            <input id={`${id}-cve`} name="cve" defaultValue={f.cve} maxLength={64} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-tech`}>ATT&amp;CK technique</label>
            <input
              id={`${id}-tech`}
              name="technique"
              defaultValue={f.technique}
              maxLength={9}
              placeholder="T1190"
            />
          </div>
          <div className="field">
            <label htmlFor={`${id}-src`}>Source</label>
            <input id={`${id}-src`} name="src" defaultValue={f.src} maxLength={64} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-min`}>Minimum confidence</label>
            <input
              id={`${id}-min`}
              name="min_confidence"
              type="number"
              min={0}
              max={100}
              defaultValue={f.min_confidence}
            />
          </div>
          {f.decoy_id ? <input type="hidden" name="decoy_id" value={f.decoy_id} /> : null}
          {f.campaign_id ? <input type="hidden" name="campaign_id" value={f.campaign_id} /> : null}
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {f.decoy_id || f.campaign_id ? (
          <p className="hint panel__body">
            Showing attempts for {f.decoy_id ? `decoy ${f.decoy_id}` : `campaign ${f.campaign_id}`}.
          </p>
        ) : null}
        {d.truncated ? (
          <Notice kind="warn">
            <p>
              The window held more capture events than the API reads in one request. Narrow the
              window or add filters to see everything.
            </p>
          </Notice>
        ) : null}
        {d.error ? <ErrorState what="Attempts" error={d.error} /> : null}
        {!d.error && d.attempts.length === 0 ? (
          <EmptyState>
            <p>No attempts in this window. Widen the window or clear filters.</p>
          </EmptyState>
        ) : null}
        {d.attempts.length ? (
          <AttemptsTable items={d.attempts} caption="Attempts, newest first" window={d.window} />
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Attempts" />;
}
