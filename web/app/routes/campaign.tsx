import { useId } from "react";
import { Form, Link } from "react-router";
import { ConfidenceMeter } from "../components/ConfidenceMeter";
import { CsrfField } from "../components/console/ConsoleShell";
import {
  AttemptStateTag,
  Facts,
  PageHead,
  SubmitButton,
  Time,
} from "../components/console/Controls";
import { LinkExplainer } from "../components/console/LinkExplainer";
import { ActionNotice, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { windowQuery } from "../components/console/Tables";
import type {
  Campaign,
  CampaignActionKind,
  CampaignActionRequest,
  CampaignStatus,
  Counted,
  Feedback,
} from "../lib/api-types";
import { field, load, must, oneOf, requireMutation, requireOperator } from "../lib/console.server";
import { words } from "../lib/format";
import { ID_PATTERNS, isId } from "../lib/ids";
import { campaignSentence, confidenceOf, ledger } from "../lib/links";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/campaign";

export function meta({ params }: Route.MetaArgs) {
  return [{ title: `Campaign ${params.campaignId} · Foiled console` }];
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
  const id = args.params.campaignId;
  const w = windowOf(args.request);
  const campaign = await must(args.request, op.api.getCampaign(id, w));
  const actions = await load(args.request, op.api.listCampaignActions(id));
  const evidence =
    "stub" in campaign ? null : await load(args.request, op.api.getCampaignEvidence(id, w));
  return {
    campaign,
    window: w,
    evidence,
    actions,
    canAct: op.can("campaigns:write"),
  };
}

const STATUSES: readonly CampaignStatus[] = ["emerging", "active", "closed"];
const FEEDBACK: readonly Feedback[] = ["true_positive", "false_positive", "unsure"];
const INTENTS: readonly CampaignActionKind[] = ["label", "status", "merge", "split", "feedback"];

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const intent = oneOf(op.form, "intent", INTENTS);
  const note = field(op.form, "note", 1000);
  const fail = (message: string) => ({ intent: intent ?? "", ok: false, message });
  if (!intent) return fail("Unknown action.");
  if (!note) return fail("Add a note: every campaign action is audited.");
  const body: CampaignActionRequest = { action: intent, note };
  if (intent === "label") {
    const title = field(op.form, "title", 200);
    if (!title || title.length > 120) return fail("A title of 1 to 120 characters is required.");
    body.title = title;
  } else if (intent === "status") {
    const s = field(op.form, "status", 16);
    if (s && !STATUSES.includes(s as CampaignStatus)) return fail("Pick a status.");
    body.status = (s as CampaignStatus | undefined) ?? null;
  } else if (intent === "feedback") {
    const f = oneOf(op.form, "feedback", FEEDBACK);
    if (!f) return fail("Pick feedback.");
    body.feedback = f;
  } else if (intent === "merge") {
    const ids = (field(op.form, "campaign_ids", 1000) ?? "").split(/[\s,]+/).filter(Boolean);
    if (ids.length < 1 || ids.length > 20 || !ids.every((x) => ID_PATTERNS.campaign.test(x))) {
      return fail("List 1 to 20 campaign ids (cmp_...).");
    }
    if (ids.includes(args.params.campaignId)) return fail("A campaign cannot merge into itself.");
    body.campaign_ids = ids;
  } else if (intent === "split") {
    const ids = op.form.getAll("attempt_ids").map(String);
    if (ids.length < 1 || ids.length > 500 || !ids.every((x) => isId("attempt", x))) {
      return fail("Tick at least one member attempt to split out.");
    }
    body.attempt_ids = ids;
  }
  const res = await load(
    args.request,
    op.api.actOnCampaign(args.params.campaignId, body, windowOf(args.request)),
  );
  if (!res.ok) return fail(res.error.message);
  return {
    intent,
    ok: true,
    message: res.data.campaign
      ? `Recorded ${intent} as ${res.data.action.action_id}.`
      : `Recorded ${intent}. The campaign no longer exists in this window.`,
  };
}

function CountedList({ label, c }: { label: string; c: Counted }) {
  if (!c.count) return null;
  return (
    <li>
      {label} ({c.count}): <span className="mono">{c.values.map(toPrintable).join(", ")}</span>
      {c.count > c.values.length ? <span className="muted"> and more</span> : null}
    </li>
  );
}

export default function CampaignPage({ loaderData: d, actionData }: Route.ComponentProps) {
  const c = d.campaign;
  const wq = windowQuery(d.window);
  if ("stub" in c) {
    const around = windowQuery({ since: c.first_seen - 3600_000, until: c.last_seen + 3600_000 });
    return (
      <>
        <PageHead title={<span className="mono">{c.campaign_id}</span>} />
        <Notice kind="info" title="Outside this window">
          <p>
            Fewer than two of this campaign's {c.attempt_count} attempts are in the current window.
            It was seen from <Time ms={c.first_seen} /> to <Time ms={c.last_seen} />.
          </p>
          {c.merged_into ? (
            <p>
              It was merged into{" "}
              <Link className="link mono" to={`/campaigns/${c.merged_into}`}>
                {c.merged_into}
              </Link>
              .
            </p>
          ) : null}
          <p>
            <Link className="link" to={`/campaigns/${c.campaign_id}${around}`}>
              Load the window around it
            </Link>
          </p>
        </Notice>
      </>
    );
  }
  const conf = confidenceOf(c.confidence);
  const fs = c.feature_summary;
  const result = (intent: string) =>
    actionData && actionData.intent === intent ? actionData : null;
  return (
    <>
      <PageHead title={toPrintable(c.title)}>
        <span className="mono muted">{c.campaign_id}</span> <span className="tag">{c.status}</span>
      </PageHead>
      <div className="split">
        <ConfidenceMeter
          level={conf.level}
          score={conf.score}
          subject={c.campaign_id}
          wording={campaignSentence(c.confidence.score, c.confidence.wording)}
          evidence={
            d.evidence?.ok
              ? ledger(d.evidence.data.confidence).map((r) => ({ ...r }))
              : c.confidence.evidence.map((e) => ({
                  id: e.signal_id,
                  signal: toPrintable(e.summary),
                  source: words(e.source),
                  points: e.weight,
                }))
          }
        />
        <section className="card panel" aria-label="Summary">
          <header className="panel__head">
            <h2 className="panel__title">Summary</h2>
          </header>
          <div className="panel__body">
            <Facts
              items={[
                ["First seen", <Time ms={c.first_seen} />],
                ["Last seen", <Time ms={c.last_seen} />],
                ["Attempts", String(c.attempt_ids.length)],
                ["Decoys", String(c.decoy_ids.length)],
                ["Sensors", String(c.sensor_ids.length)],
                [
                  "Targeting",
                  `${fs.targeting.pattern} (${fs.targeting.sources} sources, ${fs.targeting.attempts} attempts)`,
                ],
                [
                  "Seed",
                  <Link className="link mono" to={`/attempts/${c.seed.attempt_id}${wq}`}>
                    {c.seed.attempt_id}
                  </Link>,
                ],
              ]}
            />
            {c.confidence.caps_applied.length ? (
              <p className="hint">Caps: {c.confidence.caps_applied.map(toPrintable).join("; ")}.</p>
            ) : null}
            <p className="hint">
              Clustering alone never reaches the publish threshold: an analyst confirms a campaign
              before it leaves Foiled.
            </p>
          </div>
        </section>
      </div>

      <section className="card panel" aria-label="Shared features">
        <header className="panel__head">
          <h2 className="panel__title">Shared features</h2>
        </header>
        <div className="panel__body">
          <ul className="bullets">
            <CountedList label="Source addresses" c={fs.infrastructure.src_ips} />
            <CountedList label="Stage 2 URLs" c={fs.infrastructure.stage2_urls} />
            <CountedList label="Callback domains" c={fs.infrastructure.callback_domains} />
            <CountedList label="Callback addresses" c={fs.infrastructure.callback_ips} />
            {fs.infrastructure.asns.length ? (
              <li>
                ASNs: <span className="mono">{fs.infrastructure.asns.join(", ")}</span>
              </li>
            ) : null}
            {fs.ttp.techniques.length ? (
              <li>
                Techniques: <span className="mono">{fs.ttp.techniques.join(", ")}</span>
              </li>
            ) : null}
            <CountedList label="Behaviour fingerprints" c={fs.ttp.behaviour_fingerprints} />
            <CountedList label="Command lines" c={fs.ttp.cmdlines} />
          </ul>
          {fs.targeting.evidence.length ? (
            <>
              <h3 className="explain__h">Targeting evidence</h3>
              <ul className="bullets">
                {fs.targeting.evidence.map((e) => (
                  <li key={e}>{toPrintable(e)}</li>
                ))}
              </ul>
            </>
          ) : null}
        </div>
      </section>

      <Members campaign={c} wq={wq} canAct={d.canAct} result={result("split")} />

      <section className="card panel" aria-label="Possible associations">
        <header className="panel__head">
          <h2 className="panel__title">Actor associations</h2>
        </header>
        <div className="panel__body">
          {c.suggested_actor_links.length ? (
            <ul className="bullets">
              {c.suggested_actor_links.map((a) => (
                <li key={a.label}>
                  {a.wording === "confirmed association"
                    ? "Confirmed association"
                    : "Possible association"}{" "}
                  with <strong>{toPrintable(a.label)}</strong>
                  {a.report_urls.length ? (
                    <>
                      {" "}
                      (public reporting:{" "}
                      {a.report_urls.map((u, i) => (
                        <span key={u}>
                          {i ? ", " : ""}
                          <ExternalLink url={u} />
                        </span>
                      ))}
                      )
                    </>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              No actor associations. Clustering never names an actor; #29 adds possible associations
              with public clusters.
            </p>
          )}
        </div>
      </section>

      <Evidence evidence={d.evidence} wq={wq} canOverride={false} />

      <section className="card panel" aria-label="Analyst actions">
        <header className="panel__head">
          <h2 className="panel__title">Analyst actions</h2>
        </header>
        <div className="panel__body">
          {d.actions.ok ? (
            d.actions.data.items.length ? (
              <ol className="bullets">
                {d.actions.data.items.map((a) => (
                  <li key={a.action_id}>
                    <Time ms={a.at} /> <span className="tag">{a.kind}</span> by{" "}
                    <span className="mono">{toPrintable(a.analyst_id)}</span>
                    {a.title ? <> titled "{toPrintable(a.title)}"</> : null}
                    {a.status ? <> to {a.status}</> : null}
                    {a.feedback ? <> as {words(a.feedback)}</> : null}
                    {a.note ? <span className="muted">: {toPrintable(a.note)}</span> : null}
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted">No analyst actions yet.</p>
            )
          ) : (
            <ErrorState what="Analyst actions" error={d.actions.error} />
          )}
          {d.canAct ? <ActionForms campaign={c} result={result} /> : null}
        </div>
      </section>
    </>
  );
}

/** Report URLs from #29 are curated, but only https links are made clickable. */
function ExternalLink({ url }: { url: string }) {
  let ok = false;
  try {
    ok = new URL(url).protocol === "https:";
  } catch {
    ok = false;
  }
  const text = toPrintable(url);
  return ok ? (
    <a className="link" href={url} rel="noopener noreferrer" target="_blank">
      {text}
    </a>
  ) : (
    <span className="mono">{text}</span>
  );
}

function Members({
  campaign: c,
  wq,
  canAct,
  result,
}: {
  campaign: Campaign;
  wq: string;
  canAct: boolean;
  result: { ok: boolean; message: string } | null;
}) {
  const id = useId();
  const table = (
    <div className="table-wrap">
      <table className="data-table">
        <caption className="sr-only">Member attempts of {c.campaign_id}</caption>
        <thead>
          <tr>
            {canAct ? (
              <th scope="col">
                <span className="sr-only">Split out</span>
              </th>
            ) : null}
            <th scope="col">Attempt</th>
            <th scope="col">Source</th>
            <th scope="col">Decoy</th>
            <th scope="col">State</th>
            <th scope="col" className="num">
              Noise
            </th>
            <th scope="col">Joined by</th>
          </tr>
        </thead>
        <tbody>
          {c.members.map((m) => (
            <tr key={m.attempt_id}>
              {canAct ? (
                <td>
                  <input
                    type="checkbox"
                    name="attempt_ids"
                    value={m.attempt_id}
                    aria-label={`Split out ${m.attempt_id}`}
                  />
                </td>
              ) : null}
              <td className="mono">
                <Link className="link" to={`/attempts/${m.attempt_id}${wq}`}>
                  {m.attempt_id}
                </Link>
              </td>
              <td className="mono">{toPrintable(m.src)}</td>
              <td className="mono">{toPrintable(m.decoy_id)}</td>
              <td>
                <AttemptStateTag state={m.state} />
              </td>
              <td className="num mono">{m.noise_score ?? "n/a"}</td>
              <td className="wrap">
                {m.joined_by.length
                  ? m.joined_by.map((j) => (
                      <span key={j.signal_id} className="join">
                        <span className="tag">{words(j.feature)}</span> {j.strength}{" "}
                        <span className="mono">{toPrintable(j.display)}</span>
                      </span>
                    ))
                  : m.added_by
                    ? `added by ${toPrintable(m.added_by.analyst_id)} (${m.added_by.kind})`
                    : m.carried_over
                      ? "carried over from an earlier window"
                      : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          Members
        </h2>
      </header>
      {canAct ? (
        <Form method="post">
          <CsrfField />
          {table}
          <div className="form-grid panel__body">
            <div className="field field--wide">
              <label htmlFor={`${id}-note`}>Note for the split (required, audited)</label>
              <textarea id={`${id}-note`} name="note" maxLength={1000} rows={2} required />
            </div>
            <div className="actions-row field--wide">
              <SubmitButton intent="split">Split ticked attempts into a new campaign</SubmitButton>
            </div>
            <div className="field--wide">
              <ActionNotice result={result} />
            </div>
          </div>
        </Form>
      ) : (
        table
      )}
    </section>
  );
}

function Evidence({
  evidence,
  wq,
  canOverride,
}: {
  evidence: Route.ComponentProps["loaderData"]["evidence"];
  wq: string;
  canOverride: boolean;
}) {
  if (!evidence) return null;
  if (!evidence.ok) return <ErrorState what="Campaign evidence" error={evidence.error} />;
  const e = evidence.data;
  return (
    <section className="stack" aria-labelledby="evidence-h">
      <h2 id="evidence-h" className="section-title">
        Evidence
      </h2>
      <section className="card panel" aria-label="Bridges">
        <header className="panel__head">
          <h3 className="panel__title">Bridges (merges made permanent)</h3>
        </header>
        {e.bridges.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">Bridges</caption>
              <thead>
                <tr>
                  <th scope="col">Recorded</th>
                  <th scope="col">Feature</th>
                  <th scope="col">Attempt</th>
                  <th scope="col">With</th>
                  <th scope="col">Sides</th>
                  <th scope="col">Merged campaign</th>
                </tr>
              </thead>
              <tbody>
                {e.bridges.map((b) => (
                  <tr key={`${b.signal_id}-${b.attempt_id}-${b.with_attempt_id}`}>
                    <td className="mono muted">
                      <Time ms={b.recorded_at} />
                    </td>
                    <td>{words(b.feature)}</td>
                    <td className="mono">
                      <Link className="link" to={`/attempts/${b.attempt_id}${wq}`}>
                        {b.attempt_id}
                      </Link>
                    </td>
                    <td className="mono">
                      <Link className="link" to={`/attempts/${b.with_attempt_id}${wq}`}>
                        {b.with_attempt_id}
                      </Link>
                    </td>
                    <td className="mono">
                      {b.attempt_side} and {b.with_side}
                      {b.small_halves ? (
                        <span className="tag tag--warn"> small halves: audit</span>
                      ) : null}
                    </td>
                    <td className="mono">{b.merged_campaign_id ?? "before recording"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted panel__body">No merges recorded for this campaign.</p>
        )}
      </section>
      {e.possible_links.length ? (
        <Notice kind="info" title="Possible links refused">
          <p>
            One source alone joined these to another campaign, so they were not merged. An analyst
            may merge them.
          </p>
          <ul className="bullets">
            {e.possible_links.map((p) => (
              <li key={`${p.src}-${p.other_campaign_ids.join()}`}>
                <span className="mono">{toPrintable(p.src)}</span> links to{" "}
                {p.other_campaign_ids.map((o) => (
                  <Link key={o} className="link mono" to={`/campaigns/${o}${wq}`}>
                    {o}{" "}
                  </Link>
                ))}
              </li>
            ))}
          </ul>
        </Notice>
      ) : null}
      <h3 className="section-title section-title--sub">Member links</h3>
      {e.members.map((l) => (
        <LinkExplainer
          key={l.attempt_id}
          link={l}
          canOverride={canOverride}
          heading={`Member ${l.attempt_id}`}
        />
      ))}
      {e.truncated ? (
        <Notice kind="warn">
          <p>Evidence was cut at the read cap. Narrow the window for the full list.</p>
        </Notice>
      ) : null}
    </section>
  );
}

function ActionForms({
  campaign: c,
  result,
}: {
  campaign: Campaign;
  result: (intent: string) => { ok: boolean; message: string } | null;
}) {
  const id = useId();
  return (
    <div className="action-forms">
      <Form method="post" className="form-grid card-inset" aria-label="Rename">
        <CsrfField />
        <div className="field">
          <label htmlFor={`${id}-title`}>Title</label>
          <input
            id={`${id}-title`}
            name="title"
            maxLength={120}
            required
            defaultValue={c.analyst.title ?? ""}
          />
        </div>
        <div className="field">
          <label htmlFor={`${id}-ln`}>Note</label>
          <input id={`${id}-ln`} name="note" maxLength={1000} required />
        </div>
        <SubmitButton intent="label">Set title</SubmitButton>
        <div className="field--wide">
          <ActionNotice result={result("label")} />
        </div>
      </Form>
      <Form method="post" className="form-grid card-inset" aria-label="Status">
        <CsrfField />
        <div className="field">
          <label htmlFor={`${id}-status`}>Status</label>
          <select id={`${id}-status`} name="status" defaultValue={c.analyst.status ?? ""}>
            <option value="">Computed (clear override)</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${id}-sn`}>Note</label>
          <input id={`${id}-sn`} name="note" maxLength={1000} required />
        </div>
        <SubmitButton intent="status">Set status</SubmitButton>
        <div className="field--wide">
          <ActionNotice result={result("status")} />
        </div>
      </Form>
      <Form method="post" className="form-grid card-inset" aria-label="Feedback">
        <CsrfField />
        <fieldset className="fieldset">
          <legend>Feedback</legend>
          <label className="radio">
            <input type="radio" name="feedback" value="true_positive" required /> Confirm as one
            campaign
          </label>
          <label className="radio">
            <input type="radio" name="feedback" value="false_positive" /> Not a campaign
          </label>
          <label className="radio">
            <input type="radio" name="feedback" value="unsure" /> Unsure
          </label>
        </fieldset>
        <div className="field">
          <label htmlFor={`${id}-fn`}>Note</label>
          <input id={`${id}-fn`} name="note" maxLength={1000} required />
        </div>
        <SubmitButton intent="feedback">Record feedback</SubmitButton>
        <div className="field--wide">
          <ActionNotice result={result("feedback")} />
        </div>
      </Form>
      <Form method="post" className="form-grid card-inset" aria-label="Merge">
        <CsrfField />
        <div className="field field--wide">
          <label htmlFor={`${id}-ids`}>Campaign ids to merge into this one</label>
          <textarea
            id={`${id}-ids`}
            name="campaign_ids"
            rows={2}
            required
            aria-describedby={`${id}-ids-hint`}
            defaultValue={c.possible_links.flatMap((p) => p.other_campaign_ids).join(" ")}
          />
          <p id={`${id}-ids-hint`} className="hint">
            Up to 20, separated by spaces. Prefilled with refused possible links, if any.
          </p>
        </div>
        <div className="field">
          <label htmlFor={`${id}-mn`}>Note</label>
          <input id={`${id}-mn`} name="note" maxLength={1000} required />
        </div>
        <SubmitButton intent="merge">Merge</SubmitButton>
        <div className="field--wide">
          <ActionNotice result={result("merge")} />
        </div>
      </Form>
    </div>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Campaign" />;
}
