import { useId } from "react";
import { Form, Link } from "react-router";
import { PageHead, Time } from "../components/console/Controls";
import { EmptyState, ErrorState } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { field, load, requireOperator } from "../lib/console.server";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/audit";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Audit log · Foiled console" }];
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const p = new URL(args.request.url).searchParams;
  const filters = { action: field(p, "action", 64) ?? "", target: field(p, "target", 256) ?? "" };
  const cursor = field(p, "cursor", 256);
  const res = await load(args.request, op.api.listAudit({ ...filters, cursor, limit: 50 }));
  return {
    filters,
    items: res.ok ? res.data.items : [],
    nextCursor: res.ok ? (res.data.next_cursor ?? null) : null,
    error: res.ok ? null : res.error,
  };
}

export default function Audit({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  const next = new URLSearchParams();
  if (d.filters.action) next.set("action", d.filters.action);
  if (d.filters.target) next.set("target", d.filters.target);
  if (d.nextCursor) next.set("cursor", d.nextCursor);
  return (
    <>
      <PageHead title="Audit log">
        <span className="muted">
          Every write, refusal and console action in your tenant, newest first.
        </span>
      </PageHead>
      <section className="card panel" aria-label="Audit records">
        <Form method="get" className="filters" aria-label="Filter the audit log">
          <div className="field">
            <label htmlFor={`${id}-action`}>Action</label>
            <input
              id={`${id}-action`}
              name="action"
              defaultValue={d.filters.action}
              maxLength={64}
              placeholder="decoy.create"
            />
          </div>
          <div className="field field--grow">
            <label htmlFor={`${id}-target`}>Target</label>
            <input
              id={`${id}-target`}
              name="target"
              defaultValue={d.filters.target}
              maxLength={256}
            />
          </div>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.error ? <ErrorState what="Audit log" error={d.error} /> : null}
        {!d.error && d.items.length === 0 ? (
          <EmptyState>
            <p>No audit records match.</p>
          </EmptyState>
        ) : null}
        {d.items.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">Audit records, newest first</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Action</th>
                  <th scope="col">Target</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Job</th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((r) => (
                  <tr key={r.id}>
                    <td className="mono muted">
                      <Time ms={r.ts} />
                    </td>
                    <td className="mono">{toPrintable(r.action)}</td>
                    <td className="mono wrap">{r.target ? toPrintable(r.target) : ""}</td>
                    <td className="mono">
                      {toPrintable(r.actor_id)} <span className="muted">({r.actor_kind})</span>
                    </td>
                    <td>
                      <span className={r.outcome === "accepted" ? "tag tag--ok" : "tag tag--bad"}>
                        {r.outcome}
                      </span>
                    </td>
                    <td className="wrap">
                      {r.reason_code ? (
                        <span className="mono">{toPrintable(r.reason_code)}</span>
                      ) : null}
                      {r.reason_text ? <> {toPrintable(r.reason_text)}</> : null}
                    </td>
                    <td className="mono muted">{r.job_id ? toPrintable(r.job_id) : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {d.nextCursor ? (
          <p className="pager">
            <Link className="link" to={`/audit?${next}`}>
              Older records
            </Link>
          </p>
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Audit log" />;
}
