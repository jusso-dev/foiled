import { useId } from "react";
import { Form, Link, redirect } from "react-router";
import { ConfidenceChip } from "../components/ConfidenceChip";
import { CsrfField } from "../components/console/ConsoleShell";
import { ChecklistFields, PageHead, SubmitButton, Time } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { ReviewAction, ReviewActionRequest, ReviewItem, ReviewKind } from "../lib/api-types";
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

// The analyst review queue (docs/review-queue.md).

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
  return {
    filters,
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

export default function Review({ loaderData: d, actionData }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Review queue">
        <span className="muted">
          {d.error ? "" : `${d.total} matching. `}Highest priority first; overdue items lead.
        </span>
      </PageHead>
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
          me={d.me}
          canDecide={d.canDecide}
          result={actionData && actionData.item === item.item_id ? actionData : null}
        />
      ))}
    </>
  );
}

function SubjectLinks({ item }: { item: ReviewItem }) {
  const s = item.subject;
  const out: { to: string; text: string }[] = [];
  if (s.attempt_id && isId("attempt", s.attempt_id)) {
    out.push({ to: `/attempts/${s.attempt_id}`, text: s.attempt_id });
  }
  if (s.campaign_id && isId("campaign", s.campaign_id)) {
    out.push({ to: `/campaigns/${s.campaign_id}`, text: s.campaign_id });
  }
  if (s.ioc_id && isId("ioc", s.ioc_id)) out.push({ to: `/iocs/${s.ioc_id}`, text: s.ioc_id });
  if (s.writeup_id && isId("writeup", s.writeup_id)) {
    out.push({ to: `/writeups/${s.writeup_id}`, text: `write-up ${s.writeup_id}` });
  }
  if (s.other_campaign_id && isId("campaign", s.other_campaign_id)) {
    out.push({
      to: `/campaigns/${s.other_campaign_id}`,
      text: `merge into ${s.other_campaign_id}`,
    });
  }
  const actorSubject = s.campaign_id ?? s.attempt_id;
  if (
    item.kind === "actor_association" &&
    (isId("campaign", actorSubject) || isId("attempt", actorSubject))
  ) {
    out.push({ to: `/actors?subject_id=${actorSubject}`, text: "actor evidence" });
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
  me,
  canDecide,
  result,
}: {
  item: ReviewItem;
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
          <SubjectLinks item={item} />
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

export function ErrorBoundary() {
  return <RouteError what="Review queue" />;
}
