import { toPrintable } from "../lib/printable";
import { formatDay, isoDay } from "../lib/public-format";
import type { PublicTimelineEntry, TimelineKind } from "../lib/public-types";

const KIND_LABEL: Record<TimelineKind, string> = {
  first_seen: "First seen on Foiled sensors",
  advisory_published: "Advisory published",
  confirmed: "Confirmed by an analyst",
  published: "Published",
};

const isKind = (k: unknown): k is TimelineKind => typeof k === "string" && k in KIND_LABEL;

/** Dated milestones of a public write-up, oldest first, on the console timeline rail. */
export function PublicTimeline({
  entries,
  label,
}: {
  entries: readonly PublicTimelineEntry[];
  label: string;
}) {
  const sorted = [...entries].sort((a, b) => a.at - b.at);
  return (
    <ol className="timeline timeline--dates" aria-label={label}>
      {sorted.map((e) => {
        const kind = isKind(e.kind) ? e.kind : null;
        return (
          <li
            key={`${e.kind}-${e.at}`}
            className={kind ? `timeline__item timeline__item--${kind}` : "timeline__item"}
          >
            <time className="timeline__offset mono" dateTime={isoDay(e.at)}>
              {formatDay(e.at)}
            </time>
            <span className="timeline__marker" aria-hidden="true" />
            <div className="timeline__body">
              <div className="timeline__kind">{kind ? KIND_LABEL[kind] : "Event"}</div>
              <p className="timeline__summary">{toPrintable(String(e.label ?? ""))}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
