import { useId } from "react";
import { Form, Link, redirect } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import { PageHead, SubmitButton, Time } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { WriteUp, WriteUpStatus } from "../lib/api-types";
import { field, load, oneOf, requireMutation, requireOperator } from "../lib/console.server";
import { isId } from "../lib/ids";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/writeups";

// TODO(#35): /v0/write-ups is not on main yet. This page follows PR #84
// (docs/research-writeups.md there).

export function meta(_: Route.MetaArgs) {
  return [{ title: "Write-ups · Foiled console" }];
}

const STATUSES: readonly WriteUpStatus[] = [
  "draft",
  "review",
  "approved",
  "published",
  "withdrawn",
];
const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const status = oneOf(new URL(args.request.url).searchParams, "status", STATUSES) ?? "";
  const res = await load(args.request, op.api.listWriteUps({ status, limit: 100 }));
  return {
    status,
    items: res.ok ? res.data.items : ([] as WriteUp[]),
    error: res.ok ? null : res.error,
    canWrite: op.can("review:write"),
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const slug = field(op.form, "slug", 80);
  const title = field(op.form, "title", 160);
  if (!slug || !SLUG.test(slug)) {
    return { ok: false, message: "A slug of lower-case words joined by hyphens is required." };
  }
  const res = await load(
    args.request,
    op.api.createWriteUp({ slug, title: title ?? "", tlp: "amber" }),
  );
  if (!res.ok) return { ok: false, message: res.error.message };
  if (!isId("writeup", res.data.writeup_id))
    return { ok: false, message: "Unexpected write-up id." };
  return redirect(`/writeups/${res.data.writeup_id}`);
}

export default function WriteUps({ loaderData: d, actionData }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Write-ups">
        <span className="muted">Research write-ups: draft, second review, then publish.</span>
      </PageHead>
      <section className="card panel" aria-label="Write-ups">
        <Form method="get" className="filters" aria-label="Filter write-ups">
          <div className="field">
            <label htmlFor={`${id}-status`}>Status</label>
            <select id={`${id}-status`} name="status" defaultValue={d.status}>
              <option value="">Any</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <button type="submit" className="btn">
            Apply
          </button>
        </Form>
        {d.error ? <ErrorState what="Write-ups" error={d.error} issue={35} /> : null}
        {!d.error && d.items.length === 0 ? (
          <EmptyState>
            <p>No write-ups. Start one here or promote a review queue item.</p>
          </EmptyState>
        ) : null}
        {d.items.length ? (
          <div className="table-wrap">
            <table className="data-table">
              <caption className="sr-only">Write-ups, newest change first</caption>
              <thead>
                <tr>
                  <th scope="col">Title</th>
                  <th scope="col">Status</th>
                  <th scope="col">TLP</th>
                  <th scope="col">Author</th>
                  <th scope="col">Updated</th>
                  <th scope="col" className="num">
                    Lint errors
                  </th>
                </tr>
              </thead>
              <tbody>
                {d.items.map((w) => (
                  <tr key={w.writeup_id}>
                    <td className="wrap">
                      <Link className="link" to={`/writeups/${w.writeup_id}`}>
                        {toPrintable(w.title || "(untitled)")}
                      </Link>
                      <div className="mono muted">{toPrintable(w.slug)}</div>
                    </td>
                    <td>
                      <span className="tag">{w.status}</span>
                    </td>
                    <td className="mono">TLP:{w.tlp.toUpperCase()}</td>
                    <td className="mono">{toPrintable(w.author_id)}</td>
                    <td className="mono muted">
                      <Time ms={w.updated_at} />
                    </td>
                    <td className="num mono">
                      {(w.lint ?? []).filter((l) => l.severity === "error").length}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {d.canWrite ? (
          <Form method="post" className="form-grid" aria-label="Start a draft">
            <CsrfField />
            <div className="field">
              <label htmlFor={`${id}-slug`}>Slug</label>
              <input
                id={`${id}-slug`}
                name="slug"
                required
                maxLength={80}
                pattern="[a-z0-9]+(-[a-z0-9]+)*"
                placeholder="demo-app-upload-traversal"
              />
            </div>
            <div className="field">
              <label htmlFor={`${id}-title`}>Title</label>
              <input id={`${id}-title`} name="title" maxLength={160} />
            </div>
            <SubmitButton tone="primary">Start a draft</SubmitButton>
            <div className="field--wide">
              <ActionNotice result={actionData} />
            </div>
          </Form>
        ) : null}
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Write-ups" />;
}
