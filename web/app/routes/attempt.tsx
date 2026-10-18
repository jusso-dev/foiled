import { Link } from "react-router";
import {
  AttemptTimeline,
  type TimelineEvent,
  type TimelineKind,
} from "../components/AttemptTimeline";
import { CveRef } from "../components/CveRef";
import { AttemptStateTag, Facts, PageHead, Time } from "../components/console/Controls";
import { LinkExplainer } from "../components/console/LinkExplainer";
import { EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { IocRowsTable, windowQuery } from "../components/console/Tables";
import type {
  ConfidenceLink,
  Feedback,
  LinkKind,
  AttemptTimeline as Timeline,
} from "../lib/api-types";
import { field, load, must, oneOf, requireMutation, requireOperator } from "../lib/console.server";
import { formatOffset, words } from "../lib/format";
import { confidenceOf, sortLinks } from "../lib/links";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/attempt";

export function meta({ params }: Route.MetaArgs) {
  return [{ title: `Attempt ${params.attemptId} · Foiled console` }];
}

function windowOf(request: Request) {
  const p = new URL(request.url).searchParams;
  const n = (k: string) => {
    const v = p.get(k);
    return v && /^\d{1,16}$/.test(v) ? Number(v) : undefined;
  };
  return { since: n("since"), until: n("until") };
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const id = args.params.attemptId;
  const w = windowOf(args.request);
  const attempt = await must(args.request, op.api.getAttempt(id, w));
  const [timeline, links, iocs] = await Promise.all([
    load(args.request, op.api.getTimeline(id, w)),
    load(args.request, op.api.getLinks(id, w)),
    load(args.request, op.api.getAttemptIocs(id, w)),
  ]);
  return {
    attempt,
    window: w,
    timeline,
    links: links.ok ? { ok: true as const, data: sortLinks(links.data.items) } : links,
    iocs,
    canOverride: op.can("attempts:write"),
  };
}

const OVERRIDE_KINDS: readonly Exclude<LinkKind, "attempt_ioc">[] = [
  "attempt_cve",
  "attempt_technique",
  "attempt_actor",
  "attempt_campaign",
];
const FEEDBACK: readonly Feedback[] = ["true_positive", "false_positive", "unsure"];

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const kind = oneOf(op.form, "kind", OVERRIDE_KINDS);
  const target = field(op.form, "target", 256);
  const feedback = oneOf(op.form, "feedback", FEEDBACK);
  const note = field(op.form, "note", 1000);
  const base = { target: target ?? "", kind: kind ?? "" };
  if (!kind || !target || !feedback) return { ...base, ok: false, message: "Pick a decision." };
  if (!note) return { ...base, ok: false, message: "Add a note that says why." };
  const res = await load(
    args.request,
    op.api.overrideLink(args.params.attemptId, { kind, target, feedback, note }),
  );
  if (!res.ok) return { ...base, ok: false, message: res.error.message };
  return {
    ...base,
    ok: true,
    message: `Recorded. The link now scores ${res.data.score} and is worded "${res.data.wording}".`,
  };
}

/** Map a timeline entry to the design-system timeline's marker kinds. */
function markerKind(e: Timeline["entries"][number]): TimelineKind {
  if (e.state_change?.signal === "first_contact") return "connect";
  if (e.channel === "hook") return "hook";
  if (e.channel === "egress") return "blocked";
  if (e.channel === "quarantine" || e.channel === "filesystem") return "payload";
  if (e.state_change && e.state_change.state !== "probe") return "exploit";
  return "request";
}

function timelineEvents(
  t: Timeline,
  links: readonly ConfidenceLink[],
  hookCves: Map<string, string>,
): TimelineEvent[] {
  return t.entries.map((e) => {
    const cveId = hookCves.get(e.event.event_id);
    const link = cveId
      ? links.find((l) => l.kind === "attempt_cve" && l.target === cveId)
      : undefined;
    const change = e.state_change
      ? ` (state ${e.state_change.state} on ${words(e.state_change.signal)})`
      : "";
    return {
      id: `${e.seq}`,
      offset: formatOffset(e.t_offset_ms),
      kind: markerKind(e),
      // The API escapes summaries already; toPrintable is the console's own guard.
      summary: `${words(e.channel)}, ${e.severity}: ${toPrintable(e.summary)}${change}`,
      cve: link ? { id: toPrintable(link.target), confidence: confidenceOf(link) } : undefined,
    };
  });
}

export default function AttemptPage({ loaderData: d, actionData }: Route.ComponentProps) {
  const a = d.attempt;
  const links = d.links.ok ? d.links.data : [];
  const hookCves = new Map(
    a.hook_hits.filter((h) => h.cve_id).map((h) => [h.event_id, h.cve_id as string]),
  );
  const wq = windowQuery(d.window);
  const actors = links.filter((l) => l.kind === "attempt_actor");
  return (
    <>
      <PageHead title={<span className="mono">{a.attempt_id}</span>}>
        <AttemptStateTag state={a.state} />
      </PageHead>

      <div className="split">
        <section className="card panel" aria-label="Attempt">
          <header className="panel__head">
            <h2 className="panel__title">Attempt</h2>
          </header>
          <div className="panel__body">
            <Facts
              items={[
                ["Source", <span className="mono">{toPrintable(a.src)}</span>],
                [
                  "Decoy",
                  <Link className="link mono" to={`/decoys/${encodeURIComponent(a.decoy_id)}`}>
                    {a.decoy_id}
                  </Link>,
                ],
                ["Catalogue entry", <span className="mono">{a.catalogue_id}</span>],
                ["Kind", a.decoy_kind],
                ["Sensor", <span className="mono">{a.sensor_id ?? "research host"}</span>],
                ["First seen", <Time ms={a.first_seen} />],
                ["Last seen", <Time ms={a.last_seen} />],
                ["Events", String(a.event_ids.length)],
                [
                  "Campaign",
                  a.campaign_id ? (
                    <Link className="link mono" to={`/campaigns/${a.campaign_id}${wq}`}>
                      {a.campaign_id}
                    </Link>
                  ) : (
                    "none"
                  ),
                ],
              ]}
            />
            {Object.keys(a.labels).length ? (
              <>
                <h3 className="explain__h">Labels</h3>
                <ul className="bullets">
                  {Object.entries(a.labels).map(([k, v]) => (
                    <li key={k}>
                      <span className="mono">{toPrintable(k)}</span>: {toPrintable(v)}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        </section>
        <section className="card panel" aria-label="State and noise">
          <header className="panel__head">
            <h2 className="panel__title">State and noise</h2>
          </header>
          <div className="panel__body">
            <ol className="bullets">
              {a.state_history.map((s) => (
                <li key={`${s.state}-${s.event_id}`}>
                  <AttemptStateTag state={s.state} /> on {words(s.signal)} at <Time ms={s.at} />{" "}
                  <span className="muted mono">({toPrintable(s.event_id)})</span>
                </li>
              ))}
            </ol>
            {a.noise ? (
              <>
                <h3 className="explain__h">Noise</h3>
                <p>
                  {a.noise.band === "mass"
                    ? "Mass scanning: this source hit many decoys."
                    : a.noise.band === "targeted"
                      ? "Targeted: this source touched few decoys."
                      : "Mixed: some breadth across decoys."}{" "}
                  Score {a.noise.score}, {a.noise.decoys_touched} decoys and{" "}
                  {a.noise.decoy_types_touched} products touched ({a.noise.fleet_scope} scope).
                </p>
                <ul className="bullets">
                  {a.noise.evidence.map((e) => (
                    <li key={e}>{toPrintable(e)}</li>
                  ))}
                </ul>
              </>
            ) : null}
            <h3 className="explain__h">Hook hits</h3>
            {a.hook_hits.length ? (
              <ul className="bullets">
                {a.hook_hits.map((h) => {
                  const link = h.cve_id
                    ? links.find((l) => l.kind === "attempt_cve" && l.target === h.cve_id)
                    : undefined;
                  return (
                    <li key={`${h.hook_id}-${h.event_id}`}>
                      <span className="mono">{toPrintable(h.hook_id)}</span> at {words(h.stage)}
                      {link ? (
                        <>
                          {" "}
                          <CveRef id={toPrintable(link.target)} confidence={confidenceOf(link)} />
                        </>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="muted">No vulnerable-path hooks fired.</p>
            )}
          </div>
        </section>
      </div>

      <section className="card panel" aria-label="Timeline">
        <header className="panel__head">
          <h2 className="panel__title">Timeline</h2>
        </header>
        {d.timeline.ok ? (
          <div className="panel__body">
            {d.timeline.data.entries.length ? (
              <AttemptTimeline
                label={`Timeline for ${a.attempt_id}`}
                events={timelineEvents(d.timeline.data, links, hookCves)}
              />
            ) : (
              <EmptyState>
                <p>No events in this window.</p>
              </EmptyState>
            )}
            {d.timeline.data.missing_event_ids.length ? (
              <Notice kind="warn">
                <p>
                  {d.timeline.data.missing_event_ids.length} events were not found, for example
                  removed by the retention purge.
                </p>
              </Notice>
            ) : null}
            {d.timeline.data.notes.map((n) => (
              <p key={n} className="hint">
                {toPrintable(n)}
              </p>
            ))}
            <h3 className="explain__h">Packet capture slice</h3>
            <Facts
              items={[
                [
                  "Filter",
                  <code className="mono">
                    {d.timeline.data.pcap.filter || "(source is not an IP)"}
                  </code>,
                ],
                ["From", <Time ms={d.timeline.data.pcap.from_ms} />],
                ["To", <Time ms={d.timeline.data.pcap.to_ms} />],
                [
                  "R2 prefix",
                  <code className="mono">{toPrintable(d.timeline.data.pcap.r2_prefix)}</code>,
                ],
                [
                  "Output",
                  <code className="mono">{toPrintable(d.timeline.data.pcap.output_path)}</code>,
                ],
              ]}
            />
          </div>
        ) : (
          <ErrorState what="Timeline" error={d.timeline.error} />
        )}
      </section>

      <section aria-labelledby="links-h" className="stack">
        <h2 id="links-h" className="section-title">
          CVE, technique, campaign and actor links
        </h2>
        <p className="hint">
          Every score below lists its contributions, caps and evidence. Links stay "we assess as"
          until an analyst confirms them. Actor links are only ever a "possible association".
        </p>
        {!d.links.ok ? <ErrorState what="Links" error={d.links.error} /> : null}
        {d.links.ok && links.length === 0 ? (
          <EmptyState>
            <p>No scored links yet. Links appear when hooks, signatures or priors match.</p>
          </EmptyState>
        ) : null}
        {links.map((l) => (
          <LinkExplainer
            key={`${l.kind}:${l.target}`}
            link={l}
            canOverride={d.canOverride}
            result={
              actionData && actionData.kind === l.kind && actionData.target === l.target
                ? actionData
                : null
            }
          />
        ))}
        {d.links.ok && actors.length === 0 ? (
          <p className="hint">
            No actor associations. When #29 adds them they appear here as possible associations with
            named public clusters, never as fact.
          </p>
        ) : null}
      </section>

      <section className="card panel" aria-label="Indicators">
        <header className="panel__head">
          <h2 className="panel__title">Indicators</h2>
          <Link className="panel__action" to={`/iocs?attempt_id=${a.attempt_id}`}>
            Search IOCs
          </Link>
        </header>
        {d.iocs.ok ? (
          <>
            {d.iocs.data.file_ioc_limited ? (
              <Notice kind="info">
                {d.iocs.data.notes.map((n) => (
                  <p key={n}>{toPrintable(n)}</p>
                ))}
              </Notice>
            ) : null}
            {d.iocs.data.items.length ? (
              <IocRowsTable
                items={d.iocs.data.items}
                caption={`Indicators from ${a.attempt_id}`}
                window={d.window}
              />
            ) : (
              <EmptyState>
                <p>No indicators extracted from this attempt.</p>
              </EmptyState>
            )}
          </>
        ) : (
          <ErrorState what="Indicators" error={d.iocs.error} />
        )}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Attempt" />;
}
