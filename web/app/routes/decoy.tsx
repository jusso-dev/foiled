import { useEffect, useId } from "react";
import { Form, Link, useRevalidator } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import {
  DecoyStateTag,
  Facts,
  PageHead,
  ReasonFields,
  SETTLING,
  SubmitButton,
  Time,
} from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { DecoyAction, ReasonCode } from "../lib/api-types";
import { field, load, must, oneOf, requireMutation, requireOperator } from "../lib/console.server";
import { formatDuration } from "../lib/format";
import { toPrintable } from "../lib/printable";
import { REASON_CODES } from "../lib/reasons";
import { randomToken } from "../lib/session.server";
import type { Route } from "./+types/decoy";

export function meta({ params }: Route.MetaArgs) {
  return [{ title: `Decoy ${params.decoyId} · Foiled console` }];
}

const ACTIONS: readonly { action: DecoyAction; label: string; note: string; danger: boolean }[] = [
  {
    action: "reset",
    label: "Reset",
    note: "Restore the decoy from its clean image. Same id, next generation.",
    danger: false,
  },
  {
    action: "rotate",
    label: "Rotate",
    note: "Replace the decoy with a fresh instance, for example after a fingerprint.",
    danger: false,
  },
  { action: "stop", label: "Stop", note: "Stop the decoy. It can be reset later.", danger: false },
  {
    action: "mark-compromised",
    label: "Mark compromised",
    note: "Quarantine the decoy for review. Evidence is kept.",
    danger: true,
  },
  {
    action: "destroy",
    label: "Tear down",
    note: "Destroy the decoy. Final: evidence already captured is kept.",
    danger: true,
  },
];

/** How often the page refreshes while a decoy is still settling. */
const POLL_MS = 5000;

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const decoy = await must(args.request, op.api.getDecoy(args.params.decoyId));
  const audit = await load(args.request, op.api.listAudit({ target: decoy.id, limit: 20 }));
  return {
    decoy,
    audit: audit.ok ? audit.data.items : null,
    auditError: audit.ok ? null : audit.error,
    launched: new URL(args.request.url).searchParams.get("launched") === "1",
    // Minted per render: a double submit sends the same key, a later deliberate one a new key.
    actionKey: randomToken(),
    canWrite: op.can("decoys:write"),
    now: Date.now(),
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const act = oneOf(
    op.form,
    "intent",
    ACTIONS.map((a) => a.action),
  );
  if (!act) return { ok: false, message: "Unknown action." };
  const code = oneOf(op.form, "reason_code", REASON_CODES);
  const text = field(op.form, "reason_text", 500);
  if (!code || !text) return { ok: false, message: "A reason code and text are required." };
  if (act === "destroy" && op.form.get("confirm_destroy") !== "yes") {
    return { ok: false, message: "Tick the box to confirm the teardown." };
  }
  // The form's key was minted when the page rendered, so a double click sends one job.
  const minted = field(op.form, "idempotency_key", 100);
  const key = minted && /^[A-Za-z0-9_-]{16,100}$/.test(minted) ? `${minted}-${act}` : randomToken();
  const res = await load(
    args.request,
    op.api.decoyAction(args.params.decoyId, act, { code: code as ReasonCode, text }, key),
  );
  if (!res.ok) return { ok: false, message: res.error.message };
  return {
    ok: true,
    message: `Queued ${res.data.job_kind} as job ${res.data.job_id}. The decoy changes state when its host reports.`,
  };
}

export default function DecoyPage({ loaderData: d, actionData }: Route.ComponentProps) {
  const { decoy } = d;
  const id = useId();
  const revalidator = useRevalidator();
  const settling = SETTLING.has(decoy.state);

  // Keep the status current until the host reports the decoy settled. Paused
  // while the tab is hidden; a manual refresh link is always there too.
  useEffect(() => {
    if (!settling) return;
    const t = setInterval(() => {
      if (document.visibilityState === "visible" && revalidator.state === "idle") {
        void revalidator.revalidate();
      }
    }, POLL_MS);
    return () => clearInterval(t);
  }, [settling, revalidator]);

  const remaining = decoy.expires_at - d.now;
  return (
    <>
      <PageHead title={<span className="mono">{decoy.id}</span>}>
        <DecoyStateTag state={decoy.state} />
      </PageHead>
      {d.launched ? (
        <Notice kind="ok" title="Launch accepted">
          <p>
            {`The decoy is ${decoy.state}.`} A host agent leases the job and reports when it is
            healthy.
          </p>
        </Notice>
      ) : null}
      {settling ? (
        <Notice kind="info">
          <p>
            Waiting for the host: this page refreshes every {POLL_MS / 1000} seconds until the decoy
            settles.{" "}
            <Link className="link" to=".">
              Refresh now
            </Link>
          </p>
        </Notice>
      ) : null}
      <div className="split">
        <section className="card panel" aria-label="Status">
          <header className="panel__head">
            <h2 className="panel__title">Status</h2>
          </header>
          <div className="panel__body">
            <Facts
              items={[
                ["State", <DecoyStateTag state={decoy.state} />],
                ["Label", decoy.label ? toPrintable(decoy.label) : "none"],
                [
                  "Catalogue entry",
                  <Link
                    className="link mono"
                    to={`/launch?entry=${encodeURIComponent(decoy.catalogue_id)}`}
                  >
                    {decoy.catalogue_id}
                  </Link>,
                ],
                ["Kind", decoy.decoy_kind],
                ["Placed on", <span className="mono">{decoy.host_id ?? "not placed yet"}</span>],
                ["Generation", String(decoy.generation)],
                ["Created", <Time ms={decoy.created_at} />],
                ["Updated", <Time ms={decoy.updated_at} />],
                [
                  "Expires",
                  <span>
                    <Time ms={decoy.expires_at} />{" "}
                    <span className="muted">
                      {remaining > 0 ? `(in ${formatDuration(remaining)})` : "(due to rotate)"}
                    </span>
                  </span>,
                ],
                ["Created by", <span className="mono">{decoy.created_by}</span>],
              ]}
            />
            <p>
              <Link className="link" to={`/attempts?decoy_id=${encodeURIComponent(decoy.id)}`}>
                Attempts against this decoy
              </Link>
            </p>
          </div>
        </section>
        <section className="card panel" aria-labelledby={`${id}-actions`}>
          <header className="panel__head">
            <h2 id={`${id}-actions`} className="panel__title">
              Actions and teardown
            </h2>
          </header>
          <div className="panel__body">
            {decoy.state === "destroyed" ? (
              <p className="muted">This decoy is destroyed. Launch a new one from the catalogue.</p>
            ) : !d.canWrite ? (
              <p className="muted">Your token does not have decoys:write.</p>
            ) : (
              <Form method="post" className="form-grid">
                <CsrfField />
                <input type="hidden" name="idempotency_key" value={d.actionKey} />
                <ReasonFields idPrefix={`${id}-reason`} />
                <label className="check field--wide">
                  <input type="checkbox" name="confirm_destroy" value="yes" /> I understand tear
                  down is final (needed for Tear down only)
                </label>
                <ul className="action-list field--wide">
                  {ACTIONS.map((a) => (
                    <li key={a.action}>
                      <SubmitButton intent={a.action} tone={a.danger ? "danger" : "default"}>
                        {a.label}
                      </SubmitButton>{" "}
                      <span className="muted">{a.note}</span>
                    </li>
                  ))}
                </ul>
                <div className="field--wide">
                  <ActionNotice result={actionData} />
                </div>
              </Form>
            )}
          </div>
        </section>
      </div>
      <section className="card panel" aria-label="Audit trail">
        <header className="panel__head">
          <h2 className="panel__title">Audit trail</h2>
          <Link className="panel__action" to={`/audit?target=${encodeURIComponent(decoy.id)}`}>
            Full audit log
          </Link>
        </header>
        {d.auditError ? <ErrorState what="Audit trail" error={d.auditError} /> : null}
        {d.audit && d.audit.length === 0 ? (
          <EmptyState>
            <p>No audit records for this decoy yet.</p>
          </EmptyState>
        ) : null}
        {d.audit?.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">Audit records for {decoy.id}</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Action</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {d.audit.map((r) => (
                  <tr key={r.id}>
                    <td className="mono muted">
                      <Time ms={r.ts} />
                    </td>
                    <td className="mono">{toPrintable(r.action)}</td>
                    <td className="mono">{toPrintable(r.actor_id)}</td>
                    <td>{r.outcome}</td>
                    <td className="wrap">
                      {r.reason_code ? (
                        <span className="mono">{toPrintable(r.reason_code)}</span>
                      ) : null}
                      {r.reason_text ? <> {toPrintable(r.reason_text)}</> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Decoy" />;
}
