import { useId } from "react";
import { Form, Link, redirect } from "react-router";
import { ConfidenceChip } from "../components/ConfidenceChip";
import { CsrfField } from "../components/console/ConsoleShell";
import { ChecklistFields, PageHead, SubmitButton, Time } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { windowQuery } from "../components/console/Tables";
import type {
  PendingAction,
  ReviewAction,
  ReviewActionRequest,
  ReviewItem,
  ReviewKind,
} from "../lib/api-types";
import {
  field,
  intField,
  load,
  oneOf,
  requireMutation,
  requireOperator,
  windowFrom,
} from "../lib/console.server";
import { formatDuration } from "../lib/format";
import { isId } from "../lib/ids";
import { levelFor } from "../lib/links";
import { toPrintable } from "../lib/printable";
import {
  checklistComplete,
  checklistFrom,
  itemWording,
  PROMOTABLE,
  REVIEW_KIND_LABEL,
  reviewSentence,
} from "../lib/review";
import type { Route } from "./+types/review";

// The analyst review queue (docs/review-queue.md), and destructive agent
// actions waiting for a human's approval (#95, docs/mcp/foiled-mcp.md).

export function meta(_: Route.MetaArgs) {
  return [{ title: "Review queue · Foiled console" }];
}

const KINDS = Object.keys(REVIEW_KIND_LABEL) as ReviewKind[];
const STATUSES = [
  "pending",
  "needs_attention",
  "open",
  "claimed",
  "snoozed",
  "approved",
  "rejected",
  "all",
] as const;
const ACTIONS: readonly ReviewAction[] = [
  "claim",
  "release",
  "approve",
  "reject",
  "snooze",
  "promote",
];
const SNOOZE_DAYS = [1, 7, 30] as const;
const PENDING_INTENTS = ["approve_pending", "reject_pending"] as const;

function windowOf(request: Request) {
  const w = windowFrom(new URL(request.url).searchParams);
  return { since: w.since, until: w.until };
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const w = windowFrom(params);
  const filters = {
    window: w.key ?? "",
    status: oneOf(params, "status", STATUSES) ?? "pending",
    kind: oneOf(params, "kind", KINDS) ?? "",
    mine: params.get("mine") === "yes",
    overdue: params.get("overdue") === "yes",
  };
  const res = await load(
    args.request,
    op.api.listReview({
      since: w.since,
      until: w.until,
      status: filters.status,
      kind: filters.kind,
      assignee: filters.mine ? "me" : undefined,
      sla_breached: filters.overdue ? true : undefined,
      limit: 100,
    }),
  );
  // Agent resets and destroys waiting for a human (#95). Read with
  // decoys:read; deciding needs decoys:write, which the API checks again.
  const pendingCursor = params.get("pending_cursor");
  const pending = op.can("decoys:read")
    ? await load(
        args.request,
        op.api.listPendingActions({
          status: "pending",
          limit: 50,
          cursor: isId("pendingAction", pendingCursor) ? pendingCursor : undefined,
        }),
      )
    : null;
  // The next page keeps the review queue's own filters.
  const nextCursor = pending?.ok ? (pending.data.next_cursor ?? null) : null;
  const pendingNext = new URLSearchParams(params);
  if (nextCursor) pendingNext.set("pending_cursor", nextCursor);
  return {
    filters,
    pending: pending?.ok ? pending.data.items : ([] as PendingAction[]),
    pendingError: pending && !pending.ok ? pending.error : null,
    pendingNext: nextCursor ? `/review?${pendingNext}` : null,
    canApprove: op.can("decoys:write"),
    window: { since: w.since, until: w.until },
    items: res.ok ? res.data.items : ([] as ReviewItem[]),
    total: res.ok ? res.data.total : 0,
    notes: res.ok ? res.data.notes : [],
    truncated: res.ok ? res.data.truncated : false,
    error: res.ok ? null : res.error,
    canDecide: op.can("review:write"),
    me: op.session.principal.id,
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const f = op.form;
  const pendingIntent = oneOf(f, "intent", PENDING_INTENTS);
  if (pendingIntent) return decidePending(args.request, op, pendingIntent);
  const itemId = f.get("item_id");
  const act = oneOf(f, "intent", ACTIONS);
  const kind = oneOf(f, "kind", KINDS);
  const base = { item: typeof itemId === "string" ? itemId : "" };
  const fail = (message: string) => ({ ...base, ok: false, message });
  if (!isId("review", itemId) || !act || !kind) return fail("Unknown review item or action.");
  const note = field(f, "note", 1000);
  const body: ReviewActionRequest = { action: act };
  const version = intField(f, "version", 0, Number.MAX_SAFE_INTEGER);
  if (version !== undefined) body.expected_version = version;
  if (note) body.note = note;
  if (act === "reject" && !note) return fail("Add a note: a rejection needs a reason.");
  if (act === "snooze" && !note) return fail("Add a note: say why you are snoozing it.");
  if (act === "approve" && kind !== "write_up" && !note) {
    return fail("Add a note: say why you approve.");
  }
  if (act === "snooze") {
    const days = Number(f.get("snooze_days"));
    if (!SNOOZE_DAYS.includes(days as (typeof SNOOZE_DAYS)[number])) {
      return fail("Pick how long to snooze for.");
    }
    body.until = Date.now() + days * 24 * 3600_000;
  }
  if (act === "approve" && kind === "campaign_label") {
    const label = field(f, "label", 200);
    if (!label || label.length > 120)
      return fail("Give the campaign a title of 1 to 120 characters.");
    body.label = label;
  }
  if (act === "approve" && kind === "write_up") {
    const checklist = checklistFrom(f);
    if (!checklistComplete(checklist)) return fail("Tick every checklist item to approve.");
    body.checklist = checklist;
  }
  const res = await load(args.request, op.api.actOnReview(itemId, body, windowOf(args.request)));
  if (!res.ok) return fail(res.error.message);
  if (act === "promote" && res.data.writeup_id && isId("writeup", res.data.writeup_id)) {
    return redirect(`/writeups/${res.data.writeup_id}?promoted=1`);
  }
  const done: Record<ReviewAction, string> = {
    claim: "Claimed.",
    assign: "Assigned.",
    release: "Released.",
    approve: "Approved.",
    reject: "Rejected.",
    snooze: "Snoozed.",
    promote: "Draft write-up started.",
  };
  const effect = res.data.effect ? ` ${res.data.effect}` : "";
  return { ...base, ok: true, message: `${done[act]}${effect} The action is in the audit log.` };
}

async function decidePending(
  request: Request,
  op: Awaited<ReturnType<typeof requireMutation>>,
  intent: (typeof PENDING_INTENTS)[number],
) {
  const pendingId = op.form.get("pending_id");
  const base = { item: typeof pendingId === "string" ? pendingId : "" };
  const fail = (message: string) => ({ ...base, ok: false, message });
  if (!isId("pendingAction", pendingId)) return fail("Unknown pending action.");
  const note = field(op.form, "note", 1000);
  const decision = intent === "approve_pending" ? "approve" : "reject";
  if (decision === "reject" && !note) return fail("Add a note: a rejection needs a reason.");
  const res = await load(request, op.api.decidePendingAction(pendingId, decision, note));
  if (!res.ok) return fail(res.error.message);
  const p = res.data;
  const message =
    p.status === "executed"
      ? `Approved. The ${p.action} is queued as job ${p.job_id ?? ""}.`
      : p.status === "failed"
        ? `Approved, but the API refused the ${p.action} (${p.error_code ?? "error"}). It did not run.`
        : p.status === "rejected"
          ? `Rejected. The ${p.action} will not run.`
          : `Recorded as ${p.status}.`;
  return {
    ...base,
    ok: p.status !== "failed",
    message: `${message} The decision is in the audit log.`,
  };
}

export default function Review({ loaderData: d, actionData }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Review queue">
        <span className="muted">
          {d.error ? "" : `${d.total} matching. `}Highest priority first; overdue items lead.
        </span>
      </PageHead>
      <PendingActions
        items={d.pending}
        error={d.pendingError}
        next={d.pendingNext}
        canApprove={d.canApprove}
        result={actionData && d.pending.some((p) => p.id === actionData.item) ? actionData : null}
        decided={
          actionData &&
          !d.pending.some((p) => p.id === actionData.item) &&
          actionData.item.startsWith("pa_")
            ? actionData
            : null
        }
      />
      <section className="card panel" aria-label="Review queue">
        <Form method="get" className="filters" aria-label="Filter the review queue">
          <div className="field">
            <label htmlFor={`${id}-status`}>Status</label>
            <select id={`${id}-status`} name="status" defaultValue={d.filters.status}>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s === "pending"
                    ? "pending (open, claimed, snoozed)"
                    : s === "needs_attention"
                      ? "needs attention"
                      : s}
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
                  {REVIEW_KIND_LABEL[k]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-window`}>Window</label>
            <select id={`${id}-window`} name="window" defaultValue={d.filters.window || "7d"}>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="31d">Last 31 days (the maximum)</option>
            </select>
          </div>
          <label className="check">
            <input type="checkbox" name="mine" value="yes" defaultChecked={d.filters.mine} /> Mine
          </label>
          <label className="check">
            <input type="checkbox" name="overdue" value="yes" defaultChecked={d.filters.overdue} />{" "}
            Overdue only
          </label>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.error ? <ErrorState what="Review queue" error={d.error} issue={35} /> : null}
        {d.truncated ? (
          <Notice kind="warn">
            <p>The window held more events than one read covers. Narrow it to see every item.</p>
          </Notice>
        ) : null}
        {d.notes.length ? (
          <Notice kind="info">
            {d.notes.map((n) => (
              <p key={n}>{toPrintable(n)}</p>
            ))}
          </Notice>
        ) : null}
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
          wq={windowQuery(d.window)}
          me={d.me}
          canDecide={d.canDecide}
          result={actionData && actionData.item === item.item_id ? actionData : null}
        />
      ))}
    </>
  );
}

function SubjectLinks({ item, wq }: { item: ReviewItem; wq: string }) {
  const s = item.subject;
  const out: { to: string; text: string }[] = [];
  if (s.attempt_id && isId("attempt", s.attempt_id)) {
    out.push({ to: `/attempts/${s.attempt_id}${wq}`, text: s.attempt_id });
  }
  if (s.campaign_id && isId("campaign", s.campaign_id)) {
    out.push({ to: `/campaigns/${s.campaign_id}${wq}`, text: s.campaign_id });
  }
  if (s.ioc_id && isId("ioc", s.ioc_id)) out.push({ to: `/iocs/${s.ioc_id}${wq}`, text: s.ioc_id });
  if (s.writeup_id && isId("writeup", s.writeup_id)) {
    out.push({ to: `/writeups/${s.writeup_id}`, text: `write-up ${s.writeup_id}` });
  }
  if (s.other_campaign_id && isId("campaign", s.other_campaign_id)) {
    out.push({
      to: `/campaigns/${s.other_campaign_id}${wq}`,
      text: s.campaign_id
        ? `fold ${s.other_campaign_id} into ${s.campaign_id}`
        : s.other_campaign_id,
    });
  }
  const actorSubject = s.campaign_id ?? s.attempt_id;
  if (
    item.kind === "actor_association" &&
    (isId("campaign", actorSubject) || isId("attempt", actorSubject))
  ) {
    const actorParams = new URLSearchParams(wq.startsWith("?") ? wq.slice(1) : "");
    actorParams.set("subject_id", String(actorSubject));
    out.push({ to: `/actors?${actorParams.toString()}`, text: "actor evidence" });
  }
  if (!out.length) return null;
  return (
    <>
      {out.map((o) => (
        <span key={o.to}>
          {" · "}
          <Link className="link mono" to={o.to}>
            {o.text}
          </Link>
        </span>
      ))}
    </>
  );
}

function ReviewCard({
  item,
  wq,
  me,
  canDecide,
  result,
}: {
  item: ReviewItem;
  wq: string;
  me: string;
  canDecide: boolean;
  result: { ok: boolean; message: string } | null;
}) {
  const id = useId();
  const sentence = reviewSentence(item);
  const decided = item.status === "approved" || item.status === "rejected";
  const stuck = item.status === "needs_attention";
  const claimedByOther =
    item.status === "claimed" && item.assignee !== null && item.assignee !== me;
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          {REVIEW_KIND_LABEL[item.kind] ?? item.kind}{" "}
          <span className="mono muted">{toPrintable(item.item_id)}</span>
        </h2>
        <span>
          <span className={decided ? "tag" : stuck ? "tag tag--bad" : "tag tag--warn"}>
            {stuck ? "needs attention" : item.status}
          </span>{" "}
          {item.sla_breached && !decided ? <span className="tag tag--bad">overdue</span> : null}
        </span>
      </header>
      <div className="panel__body">
        <p>{toPrintable(item.title)}</p>
        {sentence ? (
          <p>
            <ConfidenceChip
              level={levelFor(itemWording(item), item.band)}
              score={item.score}
              wording={sentence}
            />{" "}
            {sentence}
          </p>
        ) : null}
        <p className="muted">
          Queued <Time ms={item.created_at} /> {`(${formatDuration(item.age_ms)} ago)`}, due{" "}
          <Time ms={item.sla_due_at} /> {`(${item.sla_hours}h SLA)`}
          {item.assignee ? (
            <>
              , claimed by <span className="mono">{toPrintable(item.assignee)}</span>
            </>
          ) : null}
          {item.snoozed_until ? (
            <>
              , snoozed until <Time ms={item.snoozed_until} />
            </>
          ) : null}
          <SubjectLinks item={item} wq={wq} />
        </p>
        {stuck ? (
          <Notice kind="warn">
            <p>
              A decision on this item did not finish, or putting it back failed. Check the audit log
              for the effect, then decide it again (after a minute).
            </p>
          </Notice>
        ) : null}
        {decided ? (
          <Notice kind="info">
            <p>
              {item.status} by <span className="mono">{toPrintable(item.decided_by ?? "")}</span> at{" "}
              <Time ms={item.decided_at} />
              {item.note ? `: ${toPrintable(item.note)}` : ""}
            </p>
          </Notice>
        ) : null}
        {canDecide && !decided ? (
          claimedByOther ? (
            <p className="muted">
              Claimed by someone else. Only they or an assignment can act on it.
            </p>
          ) : (
            <Form method="post" className="form-grid">
              <CsrfField />
              <input type="hidden" name="item_id" value={item.item_id} />
              <input type="hidden" name="kind" value={item.kind} />
              <input type="hidden" name="version" value={item.version} />
              <div className="field field--wide">
                <label htmlFor={`${id}-note`}>
                  Note (audited; required to approve, reject or snooze)
                </label>
                <textarea id={`${id}-note`} name="note" maxLength={1000} rows={2} />
              </div>
              {item.kind === "campaign_label" ? (
                <div className="field">
                  <label htmlFor={`${id}-label`}>Campaign title (to approve)</label>
                  <input id={`${id}-label`} name="label" maxLength={120} />
                </div>
              ) : null}
              {item.kind === "write_up" ? <ChecklistFields /> : null}
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
                {item.status === "claimed" ? (
                  <SubmitButton intent="release">Release</SubmitButton>
                ) : (
                  <SubmitButton intent="claim">Claim</SubmitButton>
                )}
                <SubmitButton intent="approve" tone="primary">
                  {item.kind === "write_up" ? "Approve write-up" : "Approve"}
                </SubmitButton>
                <SubmitButton intent="reject" tone="danger">
                  Reject
                </SubmitButton>
                <SubmitButton intent="snooze">Snooze</SubmitButton>
                {PROMOTABLE.has(item.kind) ? (
                  <SubmitButton intent="promote">Start a write-up</SubmitButton>
                ) : null}
              </div>
              <div className="field--wide">
                <ActionNotice result={result} />
              </div>
            </Form>
          )
        ) : (
          <ActionNotice result={result} />
        )}
      </div>
    </section>
  );
}

function PendingActions({
  items,
  error,
  canApprove,
  result,
  decided,
  next,
}: {
  items: PendingAction[];
  next: string | null;
  error: { status: number; message: string; notServed: boolean } | null;
  canApprove: boolean;
  result: { item: string; ok: boolean; message: string } | null;
  decided: { ok: boolean; message: string } | null;
}) {
  if (!error && items.length === 0 && !decided) return null;
  return (
    <section className="card panel" aria-labelledby="pending-actions-h">
      <header className="panel__head">
        <h2 id="pending-actions-h" className="panel__title">
          Agent actions waiting for approval
        </h2>
        {items.length ? <span className="tag tag--warn">{items.length} pending</span> : null}
      </header>
      <div className="panel__body">
        <p className="muted">
          An MCP agent asked to reset or destroy these sandboxes. Nothing has run. Approve only if
          you asked for it: the agent may have read attacker text. Each action expires 15 minutes
          after it was asked for, runs at most once, and your decision is audited with the agent's
          token.
        </p>
        {error ? <ErrorState what="Pending actions" error={error} issue={95} /> : null}
        <ActionNotice result={decided} />
        {items.map((p) => (
          <PendingCard
            key={p.id}
            p={p}
            canApprove={canApprove}
            result={result?.item === p.id ? result : null}
          />
        ))}
        {next ? (
          <p className="pager">
            <Link className="link" to={next}>
              Older pending actions
            </Link>
          </p>
        ) : null}
      </div>
    </section>
  );
}

function PendingCard({
  p,
  canApprove,
  result,
}: {
  p: PendingAction;
  canApprove: boolean;
  result: { ok: boolean; message: string } | null;
}) {
  const id = useId();
  return (
    <article className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h3 id={`${id}-h`} className="panel__title">
          {p.action === "destroy" ? "Destroy" : "Reset"} sandbox{" "}
          {isId("opaque", p.sandbox_id) ? (
            <Link className="link mono" to={`/decoys/${p.sandbox_id}`}>
              {toPrintable(p.sandbox_id)}
            </Link>
          ) : (
            <span className="mono">{toPrintable(p.sandbox_id)}</span>
          )}
        </h3>
        <span className="mono muted">{toPrintable(p.id)}</span>
      </header>
      <div className="panel__body">
        <p>
          Asked by agent token <span className="mono">{toPrintable(p.requested_by)}</span>{" "}
          <Time ms={p.created_at} />, expires <Time ms={p.expires_at} />.
        </p>
        <p>
          Reason given by the agent ({toPrintable(p.reason.code)}):{" "}
          <q className="mono">{toPrintable(p.reason.text)}</q>
        </p>
        {canApprove ? (
          <Form method="post" className="form-grid">
            <CsrfField />
            <input type="hidden" name="pending_id" value={p.id} />
            <div className="field field--wide">
              <label htmlFor={`${id}-note`}>Note (audited; required to reject)</label>
              <textarea id={`${id}-note`} name="note" maxLength={1000} rows={2} />
            </div>
            <div className="actions-row field--wide">
              <SubmitButton intent="approve_pending" tone="danger">
                {p.action === "destroy" ? "Approve destroy" : "Approve reset"}
              </SubmitButton>
              <SubmitButton intent="reject_pending">Reject</SubmitButton>
            </div>
            <div className="field--wide">
              <ActionNotice result={result} />
            </div>
          </Form>
        ) : (
          <p className="muted">Approving needs the decoys:write scope.</p>
        )}
      </div>
    </article>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Review queue" />;
}
