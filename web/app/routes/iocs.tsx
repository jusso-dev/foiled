import { useId } from "react";
import { Form, Link } from "react-router";
import { PageHead } from "../components/console/Controls";
import { EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { IOC_TYPE_LABEL, IocRowsTable } from "../components/console/Tables";
import type { IocRole, IocType } from "../lib/api-types";
import { field, load, oneOf, requireOperator, windowFrom } from "../lib/console.server";
import { words } from "../lib/format";
import { isId } from "../lib/ids";
import type { Route } from "./+types/iocs";

export function meta(_: Route.MetaArgs) {
  return [{ title: "IOCs · Foiled console" }];
}

const TYPES = Object.keys(IOC_TYPE_LABEL) as IocType[];
const ROLES: readonly IocRole[] = [
  "source",
  "request",
  "payload",
  "callback",
  "stage2",
  "post_exploit",
  "behaviour",
];

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const w = windowFrom(params);
  const filters = {
    window: w.key ?? "",
    type: oneOf(params, "type", TYPES) ?? "",
    value: field(params, "value", 2048) ?? "",
    role: oneOf(params, "role", ROLES) ?? "",
    attempt_id: isId("attempt", params.get("attempt_id")) ? String(params.get("attempt_id")) : "",
    campaign_id: isId("campaign", params.get("campaign_id"))
      ? String(params.get("campaign_id"))
      : "",
    file_ioc_limited: params.get("file_ioc_limited") === "true" ? "true" : "",
  };
  const res = await load(
    args.request,
    op.api.searchIocs({
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
    iocs: res.ok ? res.data.items : [],
    truncated: res.ok ? res.data.truncated : false,
    error: res.ok ? null : res.error,
  };
}

export default function Iocs({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  const f = d.filters;
  return (
    <>
      <PageHead title="IOCs">
        <span className="muted">
          Indicators extracted from attempts. Values are shown defanged and escaped.
        </span>
      </PageHead>
      <section className="card panel" aria-label="IOC search">
        <Form method="get" className="filters" aria-label="Search IOCs">
          <div className="field field--grow">
            <label htmlFor={`${id}-value`}>Value</label>
            <input
              id={`${id}-value`}
              name="value"
              defaultValue={f.value}
              maxLength={2048}
              placeholder="203[.]0[.]113[.]7, hxxp://..., a hash"
              aria-describedby={`${id}-value-hint`}
            />
            <p id={`${id}-value-hint`} className="hint">
              Exact match. Defanged input is accepted.
            </p>
          </div>
          <div className="field">
            <label htmlFor={`${id}-type`}>Type</label>
            <select id={`${id}-type`} name="type" defaultValue={f.type}>
              <option value="">Any</option>
              {TYPES.map((t) => (
                <option key={t} value={t}>
                  {IOC_TYPE_LABEL[t]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-role`}>Role</label>
            <select id={`${id}-role`} name="role" defaultValue={f.role}>
              <option value="">Any</option>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {words(r)}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-window`}>Window</label>
            <select id={`${id}-window`} name="window" defaultValue={f.window || "7d"}>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="31d">Last 31 days (the maximum)</option>
            </select>
          </div>
          <label className="check">
            <input
              type="checkbox"
              name="file_ioc_limited"
              value="true"
              defaultChecked={f.file_ioc_limited === "true"}
            />{" "}
            Only from attempts without a captured file
          </label>
          {f.attempt_id ? <input type="hidden" name="attempt_id" value={f.attempt_id} /> : null}
          {f.campaign_id ? <input type="hidden" name="campaign_id" value={f.campaign_id} /> : null}
          <button type="submit" className="btn">
            Search
          </button>
        </Form>
        {f.attempt_id || f.campaign_id ? (
          <p className="hint panel__body">
            Limited to {f.attempt_id ? `attempt ${f.attempt_id}` : `campaign ${f.campaign_id}`}.{" "}
            <Link className="link" to="/iocs">
              Clear
            </Link>
          </p>
        ) : null}
        {d.truncated ? (
          <Notice kind="warn">
            <p>The window held more events than one read covers. Narrow it to see everything.</p>
          </Notice>
        ) : null}
        {d.error ? <ErrorState what="IOCs" error={d.error} /> : null}
        {!d.error && d.iocs.length === 0 ? (
          <EmptyState>
            <p>No indicators match. Check the value or widen the window.</p>
          </EmptyState>
        ) : null}
        {d.iocs.length ? (
          <IocRowsTable items={d.iocs} caption="Indicators, newest first" window={d.window} />
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="IOCs" />;
}
