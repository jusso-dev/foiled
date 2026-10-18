import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { type FeedItem, type LiveResponse, mergeFeed, nextDelay, POLL_MS } from "../../lib/live";
import { toPrintable } from "../../lib/printable";
import { LiveIndicator } from "../AppShell";
import { AttemptStateTag, Time } from "./Controls";
import { EmptyState, Notice } from "./Notice";

/**
 * Latest attempts, kept current by polling `/live` with the newest
 * `last_seen` held (docs/ui/console.md#live-feed). On failure it backs off
 * (30 s, 60 s, at most 120 s, with jitter); when the tab becomes visible
 * again it backfills at once from its cursor, so nothing seen while away is
 * lost. The server render shows the initial list and "Paused" until the
 * first poll succeeds in the browser.
 */
export function LiveFeed({ initial, cursor }: { initial: readonly FeedItem[]; cursor: number }) {
  const [items, setItems] = useState<FeedItem[]>(() => [...initial]);
  const [live, setLive] = useState(false);
  const [gap, setGap] = useState(false);
  const cursorRef = useRef(cursor);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let inFlight = false;
    const ctrl = new AbortController();

    const schedule = (ms: number) => {
      clearTimeout(timer);
      timer = setTimeout(tick, ms);
    };

    async function tick() {
      if (document.visibilityState !== "visible" || inFlight) {
        schedule(POLL_MS);
        return;
      }
      inFlight = true;
      try {
        const res = await fetch(`/live?since=${cursorRef.current}`, {
          headers: { accept: "application/json" },
          credentials: "same-origin",
          signal: ctrl.signal,
        });
        const body = (await res.json()) as LiveResponse;
        if (!body.ok) throw new Error(body.error);
        cursorRef.current = Math.max(cursorRef.current, body.cursor);
        setItems((prev) => mergeFeed(prev, body.items));
        setGap(body.gap);
        setLive(true);
        failures = 0;
      } catch {
        if (ctrl.signal.aborted) return;
        failures += 1;
        setLive(false);
      } finally {
        inFlight = false;
      }
      schedule(nextDelay(failures));
    }

    const onVisible = () => {
      if (document.visibilityState === "visible") schedule(0);
    };
    document.addEventListener("visibilitychange", onVisible);
    schedule(0);
    return () => {
      ctrl.abort();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  return (
    <section className="card panel" aria-labelledby="live-feed-h">
      <header className="panel__head">
        <h2 id="live-feed-h" className="panel__title">
          Latest attempts
        </h2>
        <LiveIndicator live={live} />
      </header>
      {gap ? (
        <Notice kind="warn">
          <p>
            Some activity could not be backfilled (more than one read, or older than 31 days). Open
            Attempts for the full list.
          </p>
        </Notice>
      ) : null}
      {items.length === 0 ? (
        <EmptyState>
          <p>No attempts in the last 24 hours. New ones appear here as they arrive.</p>
        </EmptyState>
      ) : (
        <ul className="feed" aria-live="off">
          {items.map((a) => (
            <li key={a.attempt_id} className="feed__item">
              <span className="mono muted">
                <Time ms={a.last_seen} />
              </span>
              <AttemptStateTag state={a.state} />
              <span className="mono">{toPrintable(a.src)}</span>
              <span className="muted">against</span>
              <span className="mono">{toPrintable(a.catalogue_id)}</span>
              <Link className="link mono feed__link" to={`/attempts/${a.attempt_id}`}>
                {a.attempt_id}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
