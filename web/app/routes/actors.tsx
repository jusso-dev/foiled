import { useId } from "react";
import { Form, Link } from "react-router";
import { ConfidenceChip } from "../components/ConfidenceChip";
import { CsrfField } from "../components/console/ConsoleShell";
import { PageHead, SubmitButton } from "../components/console/Controls";
import { LinkExplainer } from "../components/console/LinkExplainer";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { ActorDecision, ActorLinkRecord } from "../lib/api-types";
import {
  field,
  intField,
  load,
  oneOf,
  requireMutation,
  requireOperator,
  windowFrom,
} from "../lib/console.server";
import { isId } from "../lib/ids";
import { levelFor, linkSentence } from "../lib/links";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/actors";

// Actor possible-associations (#29, docs/actor-attribution.md). Every link is a "possible association"
// with a public nexus, cluster or group until an analyst confirms it; the
// console shows the API's own `statement` and never words one as attribution.

export function meta(_: Route.MetaArgs) {
  return [{ title: "Actor associations · Foiled console" }];
}

const STATUSES = ["pending", "confirmed", "rejected"] as const;
const DECISIONS: readonly ActorDecision[] = ["confirm", "reject", "reopen"];
const LABEL_KIND = {
  nexus: "Nexus",
  cluster: "Public cluster",
  named_group: "Named group",
} as const;

function windowOf(request: Request) {
  const w = windowFrom(new URL(request.url).searchParams);
  return { since: w.since, until: w.until };
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const p = new URL(args.request.url).searchParams;
  const w = windowFrom(p);
  const subject = p.get("subject_id");
  const filters = {
    window: w.key ?? "",
    status: oneOf(p, "status", STATUSES) ?? "pending",
    subject_id: isId("campaign", subject) || isId("attempt", subject) ? String(subject) : "",
    min_confidence: intField(p, "min_confidence", 0, 100) ?? "",
  };
  const res = await load(
    args.request,
    op.api.listActorLinks({
      since: w.since,
      until: w.until,
      ...filters,
      window: undefined,
      limit: 100,
    }),
  );
  return {
    filters,
    items: res.ok ? res.data.items : ([] as ActorLinkRecord[]),
    truncated: res.ok ? res.data.truncated : false,
    error: res.ok ? null : res.error,
    canDecide: op.can("review:write"),
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const linkId = op.form.get("link_id");
  const decision = oneOf(op.form, "intent", DECISIONS);
  const note = field(op.form, "note", 1000) ?? "";
  const base = { link: typeof linkId === "string" ? linkId : "" };
  if (!isId("actorLink", linkId) || !decision)
    return { ...base, ok: false, message: "Unknown link or decision." };
  if (decision === "confirm" && !note) {
    return { ...base, ok: false, message: "Add a note: confirming needs a reason." };
  }
  const res = await load(
    args.request,
    op.api.decideActorLink(linkId, { decision, note }, windowOf(args.request)),
  );
  if (!res.ok) return { ...base, ok: false, message: res.error.message };
  return { ...base, ok: true, message: `Recorded. ${toPrintable(res.data.statement)}` };
}

export default function Actors({ loaderData: d, actionData }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Actor associations">
        <span className="muted">
          Possible associations with public reporting. Never an attribution.
        </span>
      </PageHead>
      <section className="card panel" aria-label="Actor associations">
        <Form method="get" className="filters" aria-label="Filter actor associations">
          <div className="field">
            <label htmlFor={`${id}-status`}>Status</label>
            <select id={`${id}-status`} name="status" defaultValue={d.filters.status}>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-min`}>Minimum confidence</label>
            <input
              id={`${id}-min`}
              name="min_confidence"
              type="number"
              min={0}
              max={100}
              defaultValue={d.filters.min_confidence}
            />
          </div>
          <div className="field">
            <label htmlFor={`${id}-window`}>Window</label>
            <select id={`${id}-window`} name="window" defaultValue={d.filters.window || "7d"}>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="31d">Last 31 days (the maximum)</option>
            </select>
          </div>
          {d.filters.subject_id ? (
            <input type="hidden" name="subject_id" value={d.filters.subject_id} />
          ) : null}
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.filters.subject_id ? (
          <p className="hint panel__body">
            For <span className="mono">{d.filters.subject_id}</span>.{" "}
            <Link className="link" to="/actors">
              Show all
            </Link>
          </p>
        ) : null}
        {d.error ? <ErrorState what="Actor associations" error={d.error} issue={29} /> : null}
        {d.truncated ? (
          <Notice kind="warn">
            <p>The window held more events than one read covers. Narrow it to see every link.</p>
          </Notice>
        ) : null}
        {!d.error && d.items.length === 0 ? (
          <EmptyState>
            <p>No actor associations with these filters.</p>
          </EmptyState>
        ) : null}
      </section>
      {d.items.map((l) => (
        <ActorCard
          key={l.link_id}
          link={l}
          canDecide={d.canDecide}
          result={actionData && actionData.link === l.link_id ? actionData : null}
        />
      ))}
    </>
  );
}

function ExternalLink({ url, text }: { url: string; text: string }) {
  let ok = false;
  try {
    ok = new URL(url).protocol === "https:";
  } catch {
    ok = false;
  }
  return ok ? (
    <a className="link" href={url} rel="noopener noreferrer" target="_blank">
      {toPrintable(text)}
    </a>
  ) : (
    <span>{toPrintable(text)}</span>
  );
}

function ActorCard({
  link: l,
  canDecide,
  result,
}: {
  link: ActorLinkRecord;
  canDecide: boolean;
  result: { ok: boolean; message: string } | null;
}) {
  const id = useId();
  const subjectHref =
    l.subject_kind === "campaign" && isId("campaign", l.subject_id)
      ? `/campaigns/${l.subject_id}`
      : isId("attempt", l.subject_id)
        ? `/attempts/${l.subject_id}`
        : null;
  // The chip and statement come from the API's wording; the console never upgrades it.
  const sentence = linkSentence({
    kind: "attempt_actor",
    target: l.label,
    score: l.score,
    band: l.band,
    wording: l.wording,
  });
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          {toPrintable(l.label)}{" "}
          <span className="muted">({LABEL_KIND[l.label_kind] ?? l.label_kind})</span>
        </h2>
        <span>
          <ConfidenceChip level={levelFor(l.wording, l.band)} score={l.score} wording={sentence} />{" "}
          <span className="tag">{l.status}</span>
          {l.example ? <span className="tag tag--warn"> example data</span> : null}
        </span>
      </header>
      <div className="panel__body">
        <p>{toPrintable(l.statement)}</p>
        <p className="muted">
          For {l.subject_kind}{" "}
          {subjectHref ? (
            <Link className="link mono" to={subjectHref}>
              {l.subject_id}
            </Link>
          ) : (
            <span className="mono">{toPrintable(l.subject_id)}</span>
          )}{" "}
          ({l.attempt_ids.length} attempts).{" "}
          {l.publishable ? "Publishable." : "Not publishable until confirmed."}
          {l.restricted ? " From a restricted source: shown here, never exported." : ""}
          {l.new_since_confirmation?.length
            ? ` ${l.new_since_confirmation.length} attempts joined since the confirmation and are not covered by it.`
            : ""}
        </p>
        <h3 className="explain__h">What matched</h3>
        <ul className="bullets">
          {l.matched.techniques.length ? (
            <li>
              Techniques:{" "}
              <span className="mono">
                {l.matched.techniques
                  .map((t) => `${t.id} (rarity ${t.rarity}, ${t.profiles_using} profiles)`)
                  .join(", ")}
              </span>
            </li>
          ) : null}
          {l.matched.indicators.map((i) => (
            <li key={`${i.type}-${i.display}`}>
              Indicator <span className="tag">{i.type}</span>{" "}
              <span className="mono">{toPrintable(i.display)}</span> {i.match}, weight {i.weight}
              {i.stale ? " (stale report, half weight)" : ""}
            </li>
          ))}
          {l.matched.targeting.length ? (
            <li>Targeting: {l.matched.targeting.map(toPrintable).join(", ")}</li>
          ) : null}
        </ul>
        {l.not_counted.length ? (
          <>
            <h3 className="explain__h">Not counted</h3>
            <ul className="bullets">
              {l.not_counted.map((n) => (
                <li key={n}>{toPrintable(n)}</li>
              ))}
            </ul>
          </>
        ) : null}
        <h3 className="explain__h">Public sources</h3>
        <ul className="bullets">
          {l.sources.map((s) => (
            <li key={s.url}>
              {toPrintable(s.publisher)}: <ExternalLink url={s.url} text={s.title} />{" "}
              <span className="muted">
                published {toPrintable(s.published)}, {toPrintable(s.licence)}
                {s.sha256 ? ", pinned" : ""}
              </span>
            </li>
          ))}
        </ul>
        {canDecide ? (
          <Form method="post" className="form-grid">
            <CsrfField />
            <input type="hidden" name="link_id" value={l.link_id} />
            <div className="field field--wide">
              <label htmlFor={`${id}-note`}>Note (audited; required to confirm)</label>
              <textarea id={`${id}-note`} name="note" maxLength={1000} rows={2} />
            </div>
            <div className="actions-row field--wide">
              {l.status !== "confirmed" ? (
                <SubmitButton intent="confirm" tone="primary">
                  Confirm association
                </SubmitButton>
              ) : null}
              {l.status !== "rejected" ? (
                <SubmitButton intent="reject" tone="danger">
                  Reject
                </SubmitButton>
              ) : null}
              {l.status !== "pending" ? <SubmitButton intent="reopen">Reopen</SubmitButton> : null}
            </div>
            <div className="field--wide">
              <ActionNotice result={result} />
            </div>
          </Form>
        ) : (
          <ActionNotice result={result} />
        )}
      </div>
      <details className="panel__body">
        <summary className="link">Confidence explanation</summary>
        <LinkExplainer
          link={l.confidence}
          canOverride={false}
          heading={`Score for ${l.subject_id}`}
        />
      </details>
    </section>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Actor associations" />;
}
