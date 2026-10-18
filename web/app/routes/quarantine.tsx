import { useId } from "react";
import { Form, Link } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import { Facts, PageHead, SubmitButton, Time } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { QuarantineItem } from "../lib/api-types";
import { field, load, requireMutation, requireOperator } from "../lib/console.server";
import { formatBytes } from "../lib/format";
import { isId } from "../lib/ids";
import { middleEllipsis, toPrintable } from "../lib/printable";
import type { Route } from "./+types/quarantine";

// TODO(#9): `GET /v0/quarantine` is planned. TODO(#14 follow-up): the
// one-time download endpoint is planned; see lib/api-types.ts for the shapes
// this page proposes. Until they are served the page says so.

export function meta(_: Route.MetaArgs) {
  return [{ title: "Quarantine · Foiled console" }];
}

/** Downloads are off unless the console Worker sets QUARANTINE_DOWNLOADS=on. */
function downloadsOn(env: Env): boolean {
  return env.QUARANTINE_DOWNLOADS === "on";
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const params = new URL(args.request.url).searchParams;
  const confirm = params.get("confirm");
  const res = await load(args.request, op.api.listQuarantine({ limit: 100 }));
  const items = res.ok ? res.data.items : ([] as QuarantineItem[]);
  const enabled = downloadsOn(op.env);
  const allowed = enabled && op.can("quarantine:download");
  return {
    items,
    error: res.ok ? null : res.error,
    enabled,
    allowed,
    // Step one of the double confirm: the analyst picked a file.
    confirming:
      allowed && isId("sha256", confirm) ? (items.find((i) => i.sha256 === confirm) ?? null) : null,
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  if (!downloadsOn(op.env)) return { ok: false, message: "Quarantine downloads are off." };
  if (!op.can("quarantine:download")) {
    return { ok: false, message: "Your token does not have quarantine:download." };
  }
  const sha = op.form.get("sha256");
  const typed = field(op.form, "confirm_sha256", 64)?.toLowerCase();
  const note = field(op.form, "note", 500);
  if (!isId("sha256", sha)) return { ok: false, message: "Unknown file." };
  // Second confirmation: the analyst types the full hash back.
  if (typed !== sha) return { ok: false, message: "The typed SHA-256 does not match the file." };
  if (op.form.get("ack_live") !== "yes") {
    return { ok: false, message: "Confirm that you will handle the file as live malware." };
  }
  if (!note) return { ok: false, message: "Say why you need the file. The download is audited." };
  const res = await load(
    args.request,
    op.api.downloadQuarantine(sha, { confirm_sha256: typed, note }),
  );
  if (!res.ok) return { ok: false, message: res.error.message };
  let url: URL | null = null;
  try {
    url = new URL(res.data.url);
  } catch {
    url = null;
  }
  if (url?.protocol !== "https:")
    return { ok: false, message: "The API returned an unusable link." };
  return {
    ok: true,
    message: "One-time link minted.",
    url: url.toString(),
    expiresAt: res.data.expires_at,
  };
}

export default function Quarantine({ loaderData: d, actionData }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Quarantine">
        <span className="muted">
          Captured files. They are never executed and never served publicly.
        </span>
      </PageHead>
      {!d.enabled ? (
        <Notice kind="info" title="Downloads are off">
          <p>
            Malware downloads are off by default. An operator turns them on for this console with
            the QUARANTINE_DOWNLOADS setting, and each download then needs two confirmations and the
            quarantine:download scope.
          </p>
        </Notice>
      ) : null}
      {d.confirming ? <ConfirmDownload item={d.confirming} result={actionData} /> : null}
      <section className="card panel" aria-labelledby={`${id}-h`}>
        <header className="panel__head">
          <h2 id={`${id}-h`} className="panel__title">
            Files
          </h2>
        </header>
        {d.error ? <ErrorState what="Quarantine" error={d.error} issue={9} /> : null}
        {!d.error && d.items.length === 0 ? (
          <EmptyState>
            <p>No quarantined files.</p>
          </EmptyState>
        ) : null}
        {d.items.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">Quarantined files</caption>
              <thead>
                <tr>
                  <th scope="col">SHA-256</th>
                  <th scope="col">Size</th>
                  <th scope="col">Type guess</th>
                  <th scope="col">First seen</th>
                  <th scope="col">Decoy</th>
                  <th scope="col">YARA</th>
                  <th scope="col">
                    <span className="sr-only">Download</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((q) => (
                  <tr key={q.sha256}>
                    <td className="mono" title={q.sha256}>
                      {middleEllipsis(q.sha256, 24)}
                    </td>
                    <td className="mono">{formatBytes(q.size)}</td>
                    <td>
                      {q.mime_guess ? (
                        toPrintable(q.mime_guess)
                      ) : (
                        <span className="muted">unknown</span>
                      )}
                    </td>
                    <td className="mono muted">
                      <Time ms={q.first_seen} />
                    </td>
                    <td className="mono">{toPrintable(q.decoy_id)}</td>
                    <td className="wrap">
                      {q.yara_matches?.length ? (
                        q.yara_matches.map(toPrintable).join(", ")
                      ) : (
                        <span className="muted">none</span>
                      )}
                    </td>
                    <td>
                      {d.allowed ? (
                        <Link className="btn btn--danger" to={`/quarantine?confirm=${q.sha256}`}>
                          Download<span className="sr-only"> {q.sha256}</span>
                        </Link>
                      ) : null}
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

function ConfirmDownload({
  item,
  result,
}: {
  item: QuarantineItem;
  result?: { ok: boolean; message: string; url?: string; expiresAt?: number } | null;
}) {
  const id = useId();
  return (
    <section className="card panel risk" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          Download live malware
        </h2>
      </header>
      <div className="panel__body">
        <Notice kind="warn">
          <p>
            This file was captured from an attacker. Handle it only in an isolated analysis
            environment. The download is audited with your note.
          </p>
        </Notice>
        <Facts
          items={[
            ["SHA-256", <span className="mono wrap-any">{item.sha256}</span>],
            ["Size", formatBytes(item.size)],
            ["Captured on", <span className="mono">{toPrintable(item.decoy_id)}</span>],
            [
              "Path in guest",
              item.guest_path ? (
                <span className="mono">{toPrintable(item.guest_path)}</span>
              ) : (
                "unknown"
              ),
            ],
          ]}
        />
        {result?.ok && result.url ? (
          <Notice kind="ok" title="One-time link">
            <p>
              <a className="link" href={result.url} rel="noreferrer noopener" download>
                Download {middleEllipsis(item.sha256, 16)}
              </a>{" "}
              (works once, expires <Time ms={result.expiresAt} />)
            </p>
          </Notice>
        ) : (
          <Form method="post" className="form-grid">
            <CsrfField />
            <input type="hidden" name="sha256" value={item.sha256} />
            <label className="check field--wide">
              <input type="checkbox" name="ack_live" value="yes" required /> I will handle this file
              as live malware
            </label>
            <div className="field field--wide">
              <label htmlFor={`${id}-sha`}>Type the full SHA-256 to confirm</label>
              <input
                id={`${id}-sha`}
                name="confirm_sha256"
                required
                minLength={64}
                maxLength={64}
                autoComplete="off"
                spellCheck={false}
                className="mono"
              />
            </div>
            <div className="field field--wide">
              <label htmlFor={`${id}-note`}>Why you need it (audited)</label>
              <textarea id={`${id}-note`} name="note" required maxLength={500} rows={2} />
            </div>
            <div className="actions-row field--wide">
              <Link className="btn" to="/quarantine">
                Cancel
              </Link>
              <SubmitButton tone="danger">Mint one-time link</SubmitButton>
            </div>
            <div className="field--wide">
              <ActionNotice result={result} />
            </div>
          </Form>
        )}
      </div>
    </section>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Quarantine" />;
}
