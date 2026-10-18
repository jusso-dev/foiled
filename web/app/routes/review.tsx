import { useId } from "react";
import { Form, Link } from "react-router";
import { ConfidenceChip } from "../components/ConfidenceChip";
import { CsrfField } from "../components/console/ConsoleShell";
import { PageHead, SubmitButton, Time } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { ReviewDecision, ReviewItem, ReviewKind, ReviewStatus } from "../lib/api-types";
import { field, load, oneOf, requireMutation, requireOperator } from "../lib/console.server";
import { isId } from "../lib/ids";
import { confidenceOf, KIND_LABEL, linkSentence } from "../lib/links";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/review";

// TODO(#35): the review queue API is planned. This page is built against the
// console's proposed shapes in lib/api-types.ts and shows a "not served yet"
// state until /v0/review-queue answers.

export function meta(_: Route.MetaArgs) {
  return [{ title: "Review queue · Foiled console" }];
}

const KINDS: readonly ReviewKind[] = [
  "predisclosure_candidate",
  "low_confidence_high_impact",
  "campaign_suggestion",
];
const KIND_TEXT: Record<ReviewKind, string> = {
  predisclosure_candidate: "Pre-disclosure candidate",
  low_confidence_high_impact: "Low confidence, high impact",
  campaign_suggestion: "Campaign suggestion",
};
const STATUSES: readonly ReviewStatus[] = ["open", "snoozed", "confirmed", "rejected"];
const DECISIONS: readonly ReviewDecision[] = ["confirm", "reject", "snooze"];
const SNOOZE_DAYS = [1, 7, 30] as const;

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const status = oneOf(params, "status", STATUSES) ?? "open";
  const kind = oneOf(params, "kind", KINDS) ?? "";
  const cursor = params.get("cursor")?.slice(0, 256) || undefined;
  const res = await load(args.request, op.api.listReview({ status, kind, cursor, limit: 50 }));
  return {
    filters: { status, kind },
    items: res.ok ? res.data.items : ([] as ReviewItem[]),
    nextCursor: res.ok ? (res.data.next_cursor ?? null) : null,
    error: res.ok ? null : res.error,
    canDecide: op.can("review:write"),
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const itemId = op.form.get("item_id");
  const decision = oneOf(op.form, "intent", DECISIONS);
  const note = field(op.form, "note", 1000);
  const base = { item: typeof itemId === "string" ? itemId : "" };
  if (!isId("opaque", itemId) || !decision) {
    return { ...base, ok: false, message: "Unknown review item or decision." };
  }
  if (!note) return { ...base, ok: false, message: "Add a note: every decision is audited." };
  let snoozeUntil: number | undefined;
  if (decision === "snooze") {
    const days = Number(op.form.get("snooze_days"));
    if (!SNOOZE_DAYS.includes(days as (typeof SNOOZE_DAYS)[number])) {
      return { ...base, ok: false, message: "Pick how long to snooze for." };
    }
    snoozeUntil = Date.now() + days * 24 * 3600_000;
  }
  const res = await load(
    args.request,
    op.api.actOnReview(itemId, { action: decision, note, snooze_until: snoozeUntil }),
  );
  if (!res.ok) return { ...base, ok: false, message: res.error.message };
  const done = { confirm: "Confirmed", reject: "Rejected", snooze: "Snoozed" }[decision];
  return { ...base, ok: true, message: `${done}. The decision is in the audit log.` };
}

export default function Review({ loaderData: d, actionData }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Review queue">
        <span className="muted">
          Pre-disclosure candidates, low-confidence high-impact links and campaign suggestions.
        </span>
      </PageHead>
      <section className="card panel" aria-label="Review queue">
        <Form method="get" className="filters" aria-label="Filter the review queue">
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
            <label htmlFor={`${id}-kind`}>Kind</label>
            <select id={`${id}-kind`} name="kind" defaultValue={d.filters.kind}>
              <option value="">Any</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_TEXT[k]}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.error ? <ErrorState what="Review queue" error={d.error} issue={35} /> : null}
        {!d.error && d.items.length === 0 ? (
          <EmptyState>
            <p>Nothing to review with these filters.</p>
          </EmptyState>
        ) : null}
      </section>
      {d.items.map((item) => (
        <ReviewCard
          key={item.item_id}
          item={item}
          canDecide={d.canDecide}
          result={actionData && actionData.item === item.item_id ? actionData : null}
        />
      ))}
      {d.nextCursor ? (
        <p className="pager">
          <Link
            className="link"
            to={`/review?${new URLSearchParams({ status: d.filters.status, kind: d.filters.kind, cursor: d.nextCursor })}`}
          >
            More items
          </Link>
        </p>
      ) : null}
    </>
  );
}

function ReviewCard({
  item,
  canDecide,
  result,
}: {
  item: ReviewItem;
  canDecide: boolean;
  result: { ok: boolean; message: string } | null;
}) {
  const id = useId();
  const link = item.link;
  const conf = link ? confidenceOf(link) : null;
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          {KIND_TEXT[item.kind] ?? item.kind}{" "}
          <span className="mono muted">{toPrintable(item.item_id)}</span>
        </h2>
        <span className="tag">{item.status}</span>
      </header>
      <div className="panel__body">
        <p>{toPrintable(item.summary)}</p>
        <p className="muted">
          Queued <Time ms={item.created_at} />
          {item.snoozed_until ? (
            <>
              , snoozed until <Time ms={item.snoozed_until} />
            </>
          ) : null}
          {item.attempt_id && isId("attempt", item.attempt_id) ? (
            <>
              {" "}
              ·{" "}
              <Link className="link mono" to={`/attempts/${item.attempt_id}`}>
                {item.attempt_id}
              </Link>
            </>
          ) : null}
          {item.campaign_id && isId("campaign", item.campaign_id) ? (
            <>
              {" "}
              ·{" "}
              <Link className="link mono" to={`/campaigns/${item.campaign_id}`}>
                {item.campaign_id}
              </Link>
            </>
          ) : null}
        </p>
        {link && conf ? (
          <p>
            {KIND_LABEL[link.kind]}:{" "}
            <ConfidenceChip level={conf.level} score={conf.score} wording={linkSentence(link)} />{" "}
            {linkSentence(link)}
            {link.caps_applied.length ? (
              <span className="muted"> Caps: {link.caps_applied.map(toPrintable).join("; ")}.</span>
            ) : null}
          </p>
        ) : null}
        {item.decision ? (
          <Notice kind="info">
            <p>
              {item.decision.action} by{" "}
              <span className="mono">{toPrintable(item.decision.analyst_id)}</span> at{" "}
              <Time ms={item.decision.at} />: {toPrintable(item.decision.note)}
            </p>
          </Notice>
        ) : null}
        {canDecide && (item.status === "open" || item.status === "snoozed") ? (
          <Form method="post" className="form-grid">
            <CsrfField />
            <input type="hidden" name="item_id" value={item.item_id} />
            <div className="field field--wide">
              <label htmlFor={`${id}-note`}>Note (required, audited)</label>
              <textarea id={`${id}-note`} name="note" required maxLength={1000} rows={2} />
            </div>
            <div className="field">
              <label htmlFor={`${id}-snooze`}>Snooze for</label>
              <select id={`${id}-snooze`} name="snooze_days" defaultValue="7">
                {SNOOZE_DAYS.map((n) => (
                  <option key={n} value={n}>
                    {n === 1 ? "1 day" : `${n} days`}
                  </option>
                ))}
              </select>
            </div>
            <div className="actions-row field--wide">
              <SubmitButton intent="confirm" tone="primary">
                Confirm
              </SubmitButton>
              <SubmitButton intent="reject" tone="danger">
                Reject
              </SubmitButton>
              <SubmitButton intent="snooze">Snooze</SubmitButton>
            </div>
            <div className="field--wide">
              <ActionNotice result={result} />
            </div>
          </Form>
        ) : (
          <ActionNotice result={result} />
        )}
      </div>
    </section>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Review queue" />;
}
