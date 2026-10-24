import { useId } from "react";
import { Form, Link } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import { PageHead } from "../components/console/Controls";
import { Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { requireOperator } from "../lib/console.server";
import { EXPORT_FORMATS, type ExportFormat, TLPS } from "../lib/exports";
import type { Route } from "./+types/exports";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Exports · Foiled console" }];
}

const FAILED: Record<string, string> = {
  "400": "The API refused the export settings.",
  "403":
    "Your token does not have the scope for that export. Unreviewed exports need review:write.",
  "404": "That export is not served by this API yet.",
  "429": "Rate limited. Wait and try again.",
  "502": "The API could not be reached.",
};

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const p = new URL(args.request.url).searchParams;
  const failed = p.get("failed");
  const format = p.get("format");
  return {
    canExport: op.can("exports:read"),
    canUnreviewed: op.can("review:write"),
    failed: failed
      ? {
          message:
            p.get("not_served") === "1"
              ? "This API does not serve that export format."
              : (FAILED[failed] ??
                `The API returned an error (${failed.replace(/\D/g, "").slice(0, 3)}).`),
          format: format && format in EXPORT_FORMATS ? (format as ExportFormat) : null,
        }
      : null,
  };
}

export default function Exports({ loaderData: d }: Route.ComponentProps) {
  const id = useId();
  return (
    <>
      <PageHead title="Exports">
        <span className="muted">
          Downloads for your own tooling. Every file is marked with its TLP.
        </span>
      </PageHead>
      {d.failed ? (
        <Notice kind="error" title="Export failed">
          <p>
            {d.failed.format ? `${EXPORT_FORMATS[d.failed.format].label}: ` : ""}
            {d.failed.message}
          </p>
        </Notice>
      ) : null}
      {!d.canExport ? (
        <Notice kind="warn" title="Read only">
          <p>Your token does not have exports:read.</p>
        </Notice>
      ) : null}
      <section className="card panel" aria-labelledby={`${id}-h`}>
        <header className="panel__head">
          <h2 id={`${id}-h`} className="panel__title">
            Download
          </h2>
        </header>
        {/* A native post: the response is a file download, not a page. */}
        <Form method="post" action="/exports/download" reloadDocument className="form-grid">
          <CsrfField />
          <fieldset className="fieldset field--wide">
            <legend>Format</legend>
            {(Object.keys(EXPORT_FORMATS) as ExportFormat[]).map((f, i) => (
              <label key={f} className="radio">
                <input type="radio" name="format" value={f} defaultChecked={i === 0} required />{" "}
                {EXPORT_FORMATS[f].label}
                {EXPORT_FORMATS[f].gated ? (
                  <span className="muted"> (confidence-gated)</span>
                ) : null}
              </label>
            ))}
          </fieldset>
          <div className="field">
            <label htmlFor={`${id}-days`}>Window</label>
            <select id={`${id}-days`} name="days" defaultValue="7">
              <option value="1">Last 24 hours</option>
              <option value="7">Last 7 days</option>
              <option value="31">Last 31 days (the maximum)</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-tlp`}>TLP marking</label>
            <select
              id={`${id}-tlp`}
              name="tlp"
              defaultValue="amber"
              aria-describedby={`${id}-tlp-hint`}
            >
              {TLPS.map((t) => (
                <option key={t} value={t}>
                  TLP:{t.toUpperCase()}
                </option>
              ))}
            </select>
            <p id={`${id}-tlp-hint`} className="hint">
              Applied to the gated formats. The file name carries it too.
            </p>
          </div>
          <div className="field">
            <label htmlFor={`${id}-min`}>Minimum confidence</label>
            <input id={`${id}-min`} name="min_confidence" type="number" min={0} max={100} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-state`}>Attempt state</label>
            <select id={`${id}-state`} name="state" defaultValue="">
              <option value="">Any</option>
              <option value="probe">probe</option>
              <option value="exploit">exploit</option>
              <option value="post-exploitation">post-exploitation</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-kind`}>Decoy kind</label>
            <select id={`${id}-kind`} name="decoy_kind" defaultValue="">
              <option value="">Any</option>
              <option value="sandbox">sandbox</option>
              <option value="emulation">emulation</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-cmp`}>Campaign id</label>
            <input id={`${id}-cmp`} name="campaign_id" maxLength={28} placeholder="cmp_..." />
          </div>
          <fieldset className="fieldset field--wide">
            <legend>What leaves Foiled</legend>
            <label className="check">
              <input type="checkbox" name="include_actors" value="yes" /> Include actor links
              (worded "possible association" unless confirmed)
            </label>
            <label className="check">
              <input type="checkbox" name="include_payloads" value="yes" /> Include request strings
              from payloads (hashes are always included)
            </label>
            <label className="check">
              <input
                type="checkbox"
                name="include_unreviewed"
                value="yes"
                disabled={!d.canUnreviewed}
                aria-describedby={`${id}-unrev`}
              />{" "}
              Include unreviewed links and indicators
            </label>
            <p id={`${id}-unrev`} className="hint">
              Review marker: an unreviewed export is audited, raised to TLP:AMBER+STRICT or
              stricter, and named "-unreviewed". It needs review:write
              {d.canUnreviewed ? "." : ", which your token does not have."} Without it, only
              publishable links leave (score 60 or more, never LLM-only or pre-disclosure-only).
            </p>
          </fieldset>
          <div className="actions-row field--wide">
            <button type="submit" className="btn btn--primary" disabled={!d.canExport}>
              Download
            </button>
            <Link className="link" to="/audit">
              Export audit records
            </Link>
          </div>
          <p className="hint field--wide">
            Large windows may be cut at the API's read cap. A cut file is named "-partial": narrow
            the window and download again for the rest.
          </p>
        </Form>
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Exports" />;
}
