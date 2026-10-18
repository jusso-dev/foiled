import { Link } from "react-router";
import { PageHead } from "../components/console/Controls";
import { LiveFeed } from "../components/console/LiveFeed";
import { EmptyState, ErrorState } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { DecoysTable } from "../components/console/Tables";
import { KpiCard } from "../components/KpiCard";
import { cloudflareContext } from "../context";
import { getHealth } from "../lib/api.server";
import { load, requireOperator, WINDOWS } from "../lib/console.server";
import { formatCount } from "../lib/format";
import { feedItem } from "../lib/live";
import type { Route } from "./+types/overview";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Overview · Foiled console" }];
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const { env } = args.context.get(cloudflareContext);
  const now = Date.now();
  const since = now - WINDOWS["24h"];
  const [health, decoys, attempts, campaigns, review] = await Promise.all([
    getHealth(env.API),
    load(args.request, op.api.listDecoys({ live: true, limit: 200 })),
    load(args.request, op.api.listAttempts({ since, limit: 200 })),
    load(args.request, op.api.listCampaigns({ limit: 200 })),
    load(args.request, op.api.listReview({ status: "pending", limit: 1 })),
  ]);
  const live = decoys.ok ? decoys.data.items : [];
  const att = attempts.ok ? attempts.data.items : [];
  return {
    health,
    decoys: decoys.ok ? null : decoys.error,
    attempts: attempts.ok ? null : attempts.error,
    kpi: {
      live: decoys.ok ? live.length : null,
      healthy: live.filter((d) => d.state === "healthy").length,
      attempts: attempts.ok ? att.length : null,
      attemptsCapped: attempts.ok && (attempts.data.truncated || att.length >= 200),
      exploit: att.filter((a) => a.state !== "probe").length,
      campaigns: campaigns.ok
        ? campaigns.data.items.filter((c) => c.status !== "closed").length
        : null,
      review: review.ok ? review.data.total : null,
      reviewNotServed: !review.ok && review.error.notServed,
    },
    attention: live.filter((d) =>
      ["failed", "quarantined", "pending", "starting"].includes(d.state),
    ),
    feed: att.slice(0, 20).map(feedItem),
    cursor: att.reduce((m, a) => Math.max(m, a.last_seen), since),
  };
}

export default function Overview({ loaderData: d }: Route.ComponentProps) {
  const k = d.kpi;
  const n = (v: number | null) => (v === null ? "n/a" : formatCount(v));
  return (
    <>
      <PageHead title="Overview">
        <span className="muted">
          API:{" "}
          {d.health
            ? `${d.health.status} (${d.health.service} ${d.health.version})`
            : "unreachable"}
        </span>
      </PageHead>
      <div className="kpis">
        <KpiCard
          label="Live decoys"
          value={n(k.live)}
          icon="honeypots"
          note={k.live !== null ? `${k.healthy} healthy` : undefined}
        />
        <KpiCard
          label="Exploit attempts, 24h"
          value={`${n(k.attempts)}${k.attemptsCapped ? "+" : ""}`}
          icon="activity"
          accent
        />
        <KpiCard
          label="Past probing, 24h"
          value={k.attempts === null ? "n/a" : formatCount(k.exploit)}
          icon="bolt"
        />
        <KpiCard label="Open campaigns, 7d" value={n(k.campaigns)} icon="attackers" />
        <KpiCard
          label="Review queue"
          value={k.reviewNotServed ? "n/a" : n(k.review)}
          icon="cve"
          note={k.reviewNotServed ? "not served yet (#35)" : undefined}
        />
      </div>
      <div className="split">
        {d.attempts ? (
          <ErrorState what="Latest attempts" error={d.attempts} />
        ) : (
          <LiveFeed initial={d.feed} cursor={d.cursor} />
        )}
        <section className="card panel" aria-label="Decoys needing attention">
          <header className="panel__head">
            <h2 className="panel__title">Needs attention</h2>
            <Link className="panel__action" to="/decoys">
              All decoys
            </Link>
          </header>
          {d.decoys ? <ErrorState what="Decoys" error={d.decoys} /> : null}
          {!d.decoys && d.attention.length === 0 ? (
            <EmptyState>
              <p>No decoys are failed, quarantined or still starting.</p>
            </EmptyState>
          ) : null}
          {d.attention.length ? (
            <DecoysTable
              items={d.attention}
              caption="Decoys that are failed, quarantined or starting"
            />
          ) : null}
        </section>
      </div>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Overview" />;
}
