import { useId } from "react";
import { Form, Link } from "react-router";
import { PageHead } from "../components/console/Controls";
import { EmptyState, ErrorState } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { DecoysTable } from "../components/console/Tables";
import type { DecoyState } from "../lib/api-types";
import { load, oneOf, requireOperator } from "../lib/console.server";
import type { Route } from "./+types/decoys";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Decoys · Foiled console" }];
}

const STATES: readonly DecoyState[] = [
  "pending",
  "starting",
  "healthy",
  "rotating",
  "stopped",
  "quarantined",
  "failed",
  "destroyed",
];

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const state = oneOf(params, "state", STATES);
  const live = params.get("all") !== "yes";
  const cursor = params.get("cursor")?.slice(0, 256) || undefined;
  const res = await load(args.request, op.api.listDecoys({ state, live, cursor, limit: 50 }));
  return {
    filters: { state: state ?? "", all: !live },
    decoys: res.ok ? res.data.items : [],
    nextCursor: res.ok ? (res.data.next_cursor ?? null) : null,
    error: res.ok ? null : res.error,
    canLaunch: op.can("decoys:write"),
  };
}

export default function Decoys({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  const nextParams = new URLSearchParams();
  if (d.filters.state) nextParams.set("state", d.filters.state);
  if (d.filters.all) nextParams.set("all", "yes");
  if (d.nextCursor) nextParams.set("cursor", d.nextCursor);
  return (
    <>
      <PageHead title="Decoys">
        {d.canLaunch ? (
          <Link className="btn btn--primary" to="/launch">
            Launch a decoy
          </Link>
        ) : null}
      </PageHead>
      <section className="card panel" aria-label="Decoys">
        <Form method="get" className="filters" aria-label="Filter decoys">
          <div className="field">
            <label htmlFor={`${id}-state`}>State</label>
            <select id={`${id}-state`} name="state" defaultValue={d.filters.state}>
              <option value="">Any</option>
              {STATES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <label className="check">
            <input type="checkbox" name="all" value="yes" defaultChecked={d.filters.all} /> Include
            destroyed decoys
          </label>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.error ? <ErrorState what="Decoys" error={d.error} /> : null}
        {!d.error && d.decoys.length === 0 ? (
          <EmptyState>
            <p>No decoys match. Launch one from the catalogue to start capturing attempts.</p>
          </EmptyState>
        ) : null}
        {d.decoys.length ? <DecoysTable items={d.decoys} caption="Decoys, newest first" /> : null}
        {d.nextCursor ? (
          <p className="pager">
            <Link className="link" to={`/decoys?${nextParams}`}>
              Older decoys
            </Link>
          </p>
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Decoys" />;
}
