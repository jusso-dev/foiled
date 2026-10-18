import { useId } from "react";
import { Form, Link } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import {
  ChecklistFields,
  Facts,
  PageHead,
  SubmitButton,
  Time,
} from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type {
  Tlp,
  WriteUp,
  WriteUpFields,
  WriteUpStatus,
  WriteUpTransition,
} from "../lib/api-types";
import {
  field,
  intField,
  load,
  must,
  oneOf,
  requireMutation,
  requireOperator,
} from "../lib/console.server";
import { TLPS } from "../lib/exports";
import { formatTs } from "../lib/format";
import { toPrintable } from "../lib/printable";
import { checklistComplete, checklistFrom } from "../lib/review";
import type { Route } from "./+types/writeup";

// One research write-up (docs/research-writeups.md).

export function meta({ params }: Route.MetaArgs) {
  return [{ title: `Write-up ${params.writeupId} · Foiled console` }];
}

/** Allowed moves (docs/research-writeups.md in #35). */
const MOVES: Record<WriteUpStatus, { to: WriteUpStatus; label: string }[]> = {
  draft: [{ to: "review", label: "Submit for review" }],
  review: [
    { to: "approved", label: "Approve (second reviewer)" },
    { to: "draft", label: "Send back to draft" },
  ],
  approved: [
    { to: "published", label: "Publish" },
    { to: "draft", label: "Reopen as draft" },
  ],
  published: [{ to: "withdrawn", label: "Withdraw" }],
  withdrawn: [],
};
const STATUSES = Object.keys(MOVES) as WriteUpStatus[];

const CVE = /^(CVE-\d{4}-\d{4,7}|FOILED-DEMO-\d{4})$/;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;

function list(form: FormData, name: string, re: RegExp): string[] | null {
  const raw = field(form, name, 2000) ?? "";
  const items = raw
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((s) => s.toUpperCase());
  if (items.length > 50 || !items.every((i) => re.test(i))) return null;
  return items;
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const id = args.params.writeupId;
  const writeup = await must(args.request, op.api.getWriteUp(id));
  const versions = await load(args.request, op.api.listWriteUpVersions(id));
  return {
    writeup,
    versions,
    promoted: new URL(args.request.url).searchParams.get("promoted") === "1",
    canWrite: op.can("review:write"),
    canPublish: op.can("review:publish"),
    me: op.session.principal.id,
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const f = op.form;
  const intent = oneOf(f, "intent", ["edit", ...STATUSES] as const);
  const version = intField(f, "version", 1, Number.MAX_SAFE_INTEGER);
  const fail = (message: string) => ({ intent: intent ?? "", ok: false, message });
  if (!intent || version === undefined) return fail("Unknown action.");
  const id = args.params.writeupId;
  if (intent === "edit") {
    const cves = list(f, "cve_ids", CVE);
    const techniques = list(f, "technique_ids", TECHNIQUE);
    if (!cves) return fail("CVE ids must look like CVE-2099-0001 or FOILED-DEMO-0001.");
    if (!techniques) return fail("Technique ids must look like T1190 or T1059.004.");
    const embargo = field(f, "embargo_until", 10);
    let embargoMs: number | null = null;
    if (embargo) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(embargo)) return fail("Embargo dates are YYYY-MM-DD.");
      embargoMs = Date.parse(`${embargo}T00:00:00Z`);
      if (!Number.isFinite(embargoMs)) return fail("Embargo dates are YYYY-MM-DD.");
    }
    const body: WriteUpFields = {
      expected_version: version,
      title: field(f, "title", 160) ?? "",
      summary: field(f, "summary", 400) ?? "",
      body_md: (typeof f.get("body_md") === "string" ? String(f.get("body_md")) : "").slice(
        0,
        65536,
      ),
      tlp: oneOf(f, "tlp", TLPS) ?? "amber",
      embargo_until: embargoMs,
      cve_ids: cves,
      technique_ids: techniques,
      redacted_payload: field(f, "redacted_payload", 2000) ?? null,
    };
    const res = await load(args.request, op.api.editWriteUp(id, body));
    if (!res.ok) return fail(res.error.message);
    const errors = (res.data.lint ?? []).filter((l) => l.severity === "error").length;
    return {
      intent,
      ok: true,
      message: `Saved as version ${res.data.version}.${errors ? ` ${errors} lint errors block submission.` : ""}`,
    };
  }
  const move: WriteUpTransition = { to: intent, expected_version: version };
  const note = field(f, "note", 1000);
  if (note) move.note = note;
  if (intent === "draft" && !note) return fail("Add a note saying what needs to change.");
  if (intent === "approved") {
    const checklist = checklistFrom(f);
    if (!checklistComplete(checklist)) return fail("Tick every checklist item to approve.");
    move.checklist = checklist;
  }
  if (intent === "published" && f.get("confirm_publish") !== "yes") {
    return fail("Tick the box to confirm publishing to the public site.");
  }
  const res = await load(args.request, op.api.transitionWriteUp(id, move));
  if (!res.ok) return fail(res.error.message);
  return { intent, ok: true, message: `Moved to ${res.data.status}. The change is audited.` };
}

export default function WriteUpPage({ loaderData: d, actionData }: Route.ComponentProps) {
  const w = d.writeup;
  const errors = (w.lint ?? []).filter((l) => l.severity === "error");
  return (
    <>
      <PageHead title={toPrintable(w.title || "(untitled write-up)")}>
        <span className="tag">{w.status}</span>{" "}
        <span className="mono muted">
          {w.writeup_id} v{w.version}
        </span>
      </PageHead>
      {d.promoted ? (
        <Notice kind="ok" title="Draft started from the review queue">
          <p>Edit the draft below, then submit it for a second review.</p>
        </Notice>
      ) : null}
      <ActionNotice result={actionData} />
      <div className="split">
        <section className="card panel" aria-label="Write-up">
          <header className="panel__head">
            <h2 className="panel__title">Details</h2>
          </header>
          <div className="panel__body">
            <Facts
              items={[
                ["Slug", <span className="mono">{toPrintable(w.slug)}</span>],
                ["TLP", `TLP:${w.tlp.toUpperCase()}`],
                ["Embargo until", w.embargo_until ? <Time ms={w.embargo_until} /> : "none"],
                ["CVEs", <span className="mono">{w.cve_ids.join(", ") || "none"}</span>],
                [
                  "Techniques",
                  <span className="mono">{w.technique_ids.join(", ") || "none"}</span>,
                ],
                ["Author", <span className="mono">{toPrintable(w.author_id)}</span>],
                [
                  "Reviewer",
                  <span className="mono">
                    {w.reviewer_id ? toPrintable(w.reviewer_id) : "none yet"}
                  </span>,
                ],
                ["Updated", <Time ms={w.updated_at} />],
                [
                  "From review item",
                  w.source_item_id ? (
                    <Link className="link mono" to="/review?status=all">
                      {w.source_item_id}
                    </Link>
                  ) : (
                    "none"
                  ),
                ],
              ]}
            />
            <p>{toPrintable(w.summary)}</p>
          </div>
        </section>
        <section className="card panel" aria-label="Lint">
          <header className="panel__head">
            <h2 className="panel__title">Lint</h2>
          </header>
          {w.lint?.length ? (
            <div className="table-wrap">
              <table className="data-table">
                <caption className="sr-only">Lint findings</caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Where</th>
                    <th scope="col">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {w.lint.map((l) => (
                    <tr key={`${l.rule}-${l.location}`}>
                      <td>
                        <span className={l.severity === "error" ? "tag tag--bad" : "tag tag--warn"}>
                          {l.severity}
                        </span>
                      </td>
                      <td className="mono">{toPrintable(l.rule)}</td>
                      <td className="mono">{toPrintable(l.location)}</td>
                      <td className="wrap">{toPrintable(l.message)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState>
              <p>No lint findings.</p>
            </EmptyState>
          )}
          {errors.length ? (
            <p className="hint panel__body">Lint errors block submit, approve and publish.</p>
          ) : null}
        </section>
      </div>
      <section className="card panel" aria-label="Body">
        <header className="panel__head">
          <h2 className="panel__title">Body (Markdown source, shown as text)</h2>
        </header>
        {/* biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard. */}
        <pre className="raw__pre" tabIndex={0}>
          <code>{toPrintable(w.body_md)}</code>
        </pre>
      </section>
      {d.canWrite && w.status === "draft" ? <EditForm writeup={w} /> : null}
      {d.canWrite ? (
        <Transitions writeup={w} me={d.me} canPublish={d.canPublish} blocked={errors.length > 0} />
      ) : null}
      <section className="card panel" aria-label="Versions">
        <header className="panel__head">
          <h2 className="panel__title">Versions</h2>
        </header>
        {d.versions.ok ? (
          <ol className="bullets panel__body">
            {d.versions.data.items.map((v) => (
              <li key={`${v.writeup.version}-${v.action}-${v.at}`}>
                v{v.writeup.version} {toPrintable(v.action)} by{" "}
                <span className="mono">{toPrintable(v.actor_id)}</span> at {formatTs(v.at)}
              </li>
            ))}
          </ol>
        ) : (
          <ErrorState what="Versions" error={d.versions.error} />
        )}
      </section>
    </>
  );
}

function EditForm({ writeup: w }: { writeup: WriteUp }) {
  const id = useId();
  const embargo = w.embargo_until ? new Date(w.embargo_until).toISOString().slice(0, 10) : "";
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          Edit draft
        </h2>
      </header>
      <Form method="post" className="form-grid">
        <CsrfField />
        <input type="hidden" name="version" value={w.version} />
        <div className="field field--wide">
          <label htmlFor={`${id}-title`}>Title</label>
          <input id={`${id}-title`} name="title" maxLength={160} defaultValue={w.title} />
        </div>
        <div className="field field--wide">
          <label htmlFor={`${id}-summary`}>Summary</label>
          <textarea
            id={`${id}-summary`}
            name="summary"
            maxLength={400}
            rows={2}
            defaultValue={w.summary}
          />
        </div>
        <div className="field field--wide">
          <label htmlFor={`${id}-body`}>Body (Markdown subset)</label>
          <textarea
            id={`${id}-body`}
            name="body_md"
            maxLength={65536}
            rows={14}
            defaultValue={w.body_md}
            aria-describedby={`${id}-body-hint`}
          />
          <p id={`${id}-body-hint`} className="hint">
            Write "we assess as" for unconfirmed CVE links and "possible association" for actors. No
            exploit code, runnable commands, tenant data or raw HTML: lint refuses them.
          </p>
        </div>
        <div className="field">
          <label htmlFor={`${id}-tlp`}>TLP</label>
          <select id={`${id}-tlp`} name="tlp" defaultValue={w.tlp}>
            {TLPS.map((t: Tlp) => (
              <option key={t} value={t}>
                TLP:{t.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${id}-embargo`}>Embargo until (UTC date)</label>
          <input id={`${id}-embargo`} name="embargo_until" type="date" defaultValue={embargo} />
        </div>
        <div className="field">
          <label htmlFor={`${id}-cves`}>CVE ids</label>
          <input id={`${id}-cves`} name="cve_ids" defaultValue={w.cve_ids.join(" ")} />
        </div>
        <div className="field">
          <label htmlFor={`${id}-tech`}>Technique ids</label>
          <input id={`${id}-tech`} name="technique_ids" defaultValue={w.technique_ids.join(" ")} />
        </div>
        <div className="field field--wide">
          <label htmlFor={`${id}-payload`}>Redacted payload (redacted again on save)</label>
          <textarea
            id={`${id}-payload`}
            name="redacted_payload"
            maxLength={2000}
            rows={3}
            defaultValue={w.redacted_payload ?? ""}
          />
        </div>
        <div className="actions-row field--wide">
          <SubmitButton intent="edit" tone="primary">
            Save draft
          </SubmitButton>
        </div>
      </Form>
    </section>
  );
}

function Transitions({
  writeup: w,
  me,
  canPublish,
  blocked,
}: {
  writeup: WriteUp;
  me: string;
  canPublish: boolean;
  blocked: boolean;
}) {
  const id = useId();
  const moves = MOVES[w.status].filter(
    (m) => (m.to !== "published" && m.to !== "withdrawn") || canPublish,
  );
  if (!moves.length) return null;
  const ownWork = w.author_id === me;
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          Workflow
        </h2>
      </header>
      <Form method="post" className="form-grid">
        <CsrfField />
        <input type="hidden" name="version" value={w.version} />
        <div className="field field--wide">
          <label htmlFor={`${id}-note`}>Note (audited; required to send back)</label>
          <textarea id={`${id}-note`} name="note" maxLength={1000} rows={2} />
        </div>
        {w.status === "review" ? (
          ownWork ? (
            <p className="hint field--wide">
              You wrote this, so a second reviewer must approve it.
            </p>
          ) : (
            <ChecklistFields />
          )
        ) : null}
        {w.status === "approved" && canPublish ? (
          <label className="check field--wide">
            <input type="checkbox" name="confirm_publish" value="yes" /> Publish to the public site
            (needs TLP:CLEAR; visible from the later of now and the embargo)
          </label>
        ) : null}
        <div className="actions-row field--wide">
          {moves.map((m) => (
            <SubmitButton
              key={m.to}
              intent={m.to}
              tone={m.to === "withdrawn" ? "danger" : m.to === "draft" ? "default" : "primary"}
            >
              {m.label}
            </SubmitButton>
          ))}
        </div>
        {blocked ? (
          <p className="hint field--wide">Fix the lint errors before moving forward.</p>
        ) : null}
      </Form>
    </section>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Write-up" />;
}
