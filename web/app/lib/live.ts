/**
 * Live feed state: merging backfilled attempts and the reconnect schedule.
 * Pure functions, so the reconnect and backfill rules in docs/ui/console.md
 * are tested without a browser.
 */

import type { Attempt } from "./api-types";

/** What the feed shows per attempt. Hostile fields stay raw; the view escapes them. */
export interface FeedItem {
  attempt_id: string;
  src: string;
  catalogue_id: string;
  decoy_kind: Attempt["decoy_kind"];
  state: Attempt["state"];
  last_seen: number;
  hook_hits: number;
}

export function feedItem(a: Attempt): FeedItem {
  return {
    attempt_id: a.attempt_id,
    src: a.src,
    catalogue_id: a.catalogue_id,
    decoy_kind: a.decoy_kind,
    state: a.state,
    last_seen: a.last_seen,
    hook_hits: a.hook_hits.length,
  };
}

export const FEED_SIZE = 20;

/** `GET /live?since=` (routes/live.tsx). */
export type LiveResponse =
  | { ok: true; items: FeedItem[]; cursor: number; gap: boolean; at: number }
  | { ok: false; error: string; signedOut?: boolean };

/**
 * Merge a backfill into the feed: an attempt seen again moves to the top with
 * its new state, new attempts are added, and the newest FEED_SIZE are kept.
 */
export function mergeFeed(current: readonly FeedItem[], incoming: readonly FeedItem[]): FeedItem[] {
  const byId = new Map(current.map((i) => [i.attempt_id, i]));
  for (const i of incoming) {
    const old = byId.get(i.attempt_id);
    if (!old || i.last_seen >= old.last_seen) byId.set(i.attempt_id, i);
  }
  return [...byId.values()].sort((a, b) => b.last_seen - a.last_seen).slice(0, FEED_SIZE);
}

/** Poll interval while connected. */
export const POLL_MS = 15_000;
/** Longest wait between retries after failures. */
export const MAX_BACKOFF_MS = 120_000;

/**
 * Delay before the next try after `failures` failures in a row: 15 s while
 * healthy, then 30 s, 60 s and at most 120 s, each with up to 20 per cent
 * jitter so many consoles reconnecting after a deploy do not arrive together.
 */
export function nextDelay(failures: number, random: () => number = Math.random): number {
  if (failures <= 0) return POLL_MS;
  const base = Math.min(MAX_BACKOFF_MS, POLL_MS * 2 ** Math.min(failures, 4));
  return Math.round(base * (1 + 0.2 * random()));
}

/**
 * Whether a `/live` answer means the session is gone (expired, revoked or
 * signed out elsewhere): a 401, a redirect followed to the sign-in page, or
 * a body that says so.
 */
export function feedSignedOut(
  status: number,
  redirected: boolean,
  body: LiveResponse | null,
): boolean {
  return status === 401 || redirected || (body !== null && !body.ok && body.signedOut === true);
}
