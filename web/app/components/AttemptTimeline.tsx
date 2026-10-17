import type { Confidence } from "../lib/confidence";
import { CveRef } from "./CveRef";

export type TimelineKind =
  | "connect"
  | "request"
  | "hook"
  | "exploit"
  | "payload"
  | "blocked"
  | "reset";

export interface TimelineEvent {
  id: string;
  /** Offset from the first packet, for example "+0.412s". */
  offset: string;
  kind: TimelineKind;
  summary: string;
  /** ATT&CK technique id, if mapped. */
  technique?: string;
  /** CVE link, always with its confidence. */
  cve?: { id: string; confidence: Confidence };
}

const KIND_LABEL: Record<TimelineKind, string> = {
  connect: "Connect",
  request: "Request",
  hook: "Hook hit",
  exploit: "Exploit",
  payload: "Payload",
  blocked: "Egress blocked",
  reset: "Sandbox reset",
};

/** Ordered attempt events with mono offsets and a coloured rail marker per kind. */
export function AttemptTimeline({
  events,
  label,
}: {
  events: readonly TimelineEvent[];
  label: string;
}) {
  return (
    <ol className="timeline" aria-label={label}>
      {events.map((e) => (
        <li key={e.id} className={`timeline__item timeline__item--${e.kind}`}>
          <span className="timeline__offset mono">{e.offset}</span>
          <span className="timeline__marker" aria-hidden="true" />
          <div className="timeline__body">
            <div className="timeline__kind">
              {KIND_LABEL[e.kind]}
              {e.technique ? <span className="tag timeline__ttp">{e.technique}</span> : null}
            </div>
            <p className="timeline__summary">{e.summary}</p>
            {e.cve ? <CveRef id={e.cve.id} confidence={e.cve.confidence} /> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}
