import { load, requireOperator, WINDOWS } from "../lib/console.server";
import { feedItem, type LiveResponse } from "../lib/live";
import type { Route } from "./+types/live";

/**
 * Live feed backfill (docs/ui/console.md#live-feed). The overview polls this
 * with the newest `last_seen` it holds; the answer is every attempt with
 * activity since then. When the `/v0/events` Durable Object stream lands
 * (#14 follow-up), the client keeps the same cursor and uses this route only
 * to backfill after a reconnect.
 */
export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const now = Date.now();
  const raw = new URL(args.request.url).searchParams.get("since");
  const asked = raw && /^\d{1,16}$/.test(raw) ? Number(raw) : now - WINDOWS["24h"];
  // The API reads at most 31 days. A client away longer gets what fits and is told.
  const floor = now - WINDOWS["31d"];
  const since = Math.min(Math.max(asked, floor), now);
  const res = await load(args.request, op.api.listAttempts({ since, limit: 50 }));
  if (!res.ok) return Response.json({ ok: false, error: res.error.message }, { status: 502 });
  const items = res.data.items.map(feedItem);
  const cursor = items.reduce((m, a) => Math.max(m, a.last_seen), asked);
  const body: LiveResponse = {
    ok: true,
    items,
    cursor,
    gap: asked < floor || res.data.truncated,
    at: now,
  };
  return Response.json(body, { headers: { "cache-control": "no-store" } });
}
