import { useId } from "react";
import { Form } from "react-router";
import type { ConfidenceLink } from "../../lib/api-types";
import { formatTs } from "../../lib/format";
import {
  confidenceOf,
  KIND_LABEL,
  ledger,
  linkSentence,
  overridable,
  SOURCE_LABEL,
} from "../../lib/links";
import { toPrintable } from "../../lib/printable";
import { ConfidenceMeter } from "../ConfidenceMeter";
import { CsrfField } from "./ConsoleShell";
import { SubmitButton } from "./Controls";
import { ActionNotice } from "./Notice";

const FEEDBACK_LABEL = {
  true_positive: "Confirm (true positive)",
  false_positive: "Reject (false positive)",
  unsure: "Unsure (record feedback only)",
} as const;

/**
 * Confidence explainability for one link (#27): the score and its wording,
 * every contribution with its points, the caps that applied, every evidence
 * item, the publish flags, any analyst override, and the override form.
 */
export function LinkExplainer({
  link,
  canOverride,
  result,
  heading,
}: {
  link: ConfidenceLink;
  canOverride: boolean;
  result?: { ok: boolean; message: string } | null;
  /** Replaces "<kind> <target>" in the header, for example a member attempt id. */
  heading?: string;
}) {
  const conf = confidenceOf(link);
  const sentence = linkSentence(link);
  const target = toPrintable(link.target);
  const formId = useId();
  return (
    <section className="card explain" aria-label={heading ?? `${KIND_LABEL[link.kind]} ${target}`}>
      <header className="panel__head">
        <h3 className="panel__title">
          {heading ? (
            <span className="mono explain__target">{heading}</span>
          ) : (
            <>
              {KIND_LABEL[link.kind]} <span className="mono explain__target">{target}</span>
            </>
          )}
        </h3>
        <span className="muted">Band {link.band}</span>
      </header>
      <ConfidenceMeter
        level={conf.level}
        score={conf.score}
        subject={target}
        wording={sentence}
        headingLevel={3}
        evidence={ledger(link).map((r) => ({
          id: r.id,
          signal: r.signal,
          source: r.source,
          points: r.points,
        }))}
      />
      <div className="explain__body">
        <h4 className="explain__h">Caps applied</h4>
        {link.caps_applied.length ? (
          <ul className="bullets">
            {link.caps_applied.map((c) => (
              <li key={c}>{toPrintable(c)}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">No caps applied.</p>
        )}

        <h4 className="explain__h">Evidence</h4>
        <table className="data-table">
          <caption className="sr-only">Evidence for {target}</caption>
          <thead>
            <tr>
              <th scope="col">Signal</th>
              <th scope="col">Source</th>
              <th scope="col" className="num">
                Weight
              </th>
              <th scope="col">Summary</th>
            </tr>
          </thead>
          <tbody>
            {link.evidence.map((e) => (
              <tr key={e.signal_id}>
                <td className="mono">{toPrintable(e.signal_id)}</td>
                <td>{SOURCE_LABEL[e.source] ?? e.source}</td>
                <td className="num mono">{e.weight}</td>
                <td className="wrap">
                  {toPrintable(e.summary)}
                  {e.ref ? <span className="muted mono"> ({toPrintable(e.ref)})</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <ul className="flags" aria-label="Publish decisions">
          <li>{link.publishable ? "Publishable in exports" : "Not publishable: stays internal"}</li>
          <li>{link.radar_queue ? "Candidate for the review queue" : "Not a review candidate"}</li>
          <li>
            {link.auto_state_promote ? "May promote the attempt state" : "Does not promote state"}
          </li>
        </ul>

        {link.override ? (
          <p className="explain__override">
            Analyst {toPrintable(link.override.analyst_id)} recorded{" "}
            <strong>{FEEDBACK_LABEL[link.override.feedback]}</strong> at{" "}
            {formatTs(link.override.at)}
            {link.override.note ? <>: "{toPrintable(link.override.note)}"</> : null}
          </p>
        ) : null}

        {canOverride && overridable(link.kind) ? (
          <Form method="post" className="override" aria-labelledby={`${formId}-legend`}>
            <CsrfField />
            <input type="hidden" name="kind" value={link.kind} />
            <input type="hidden" name="target" value={link.target} />
            <fieldset className="fieldset">
              <legend id={`${formId}-legend`}>Analyst override (audited as link.override)</legend>
              <div className="radios">
                {(Object.keys(FEEDBACK_LABEL) as (keyof typeof FEEDBACK_LABEL)[]).map((f) => (
                  <label key={f} className="radio">
                    <input type="radio" name="feedback" value={f} required /> {FEEDBACK_LABEL[f]}
                  </label>
                ))}
              </div>
              <div className="field field--wide">
                <label htmlFor={`${formId}-note`}>Note</label>
                <textarea
                  id={`${formId}-note`}
                  name="note"
                  maxLength={1000}
                  rows={2}
                  required
                  aria-describedby={`${formId}-hint`}
                />
                <p id={`${formId}-hint`} className="hint">
                  Say why. Confirming sets the score to 100 and the wording to confirmed. Rejecting
                  suppresses the link everywhere downstream.
                </p>
              </div>
            </fieldset>
            <SubmitButton intent="override" tone="primary">
              Record override
            </SubmitButton>
            <ActionNotice result={result} />
          </Form>
        ) : null}
      </div>
    </section>
  );
}
