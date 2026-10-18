import { type ReactNode, useId } from "react";
import { useNavigation } from "react-router";
import type { AttemptState, DecoyState } from "../../lib/api-types";
import { formatTs, isoTs } from "../../lib/format";
import { REASON_LABEL } from "../../lib/reasons";
import { CHECKLIST } from "../../lib/review";

const DECOY_TONE: Record<DecoyState, "ok" | "warn" | "bad" | "plain"> = {
  pending: "warn",
  starting: "warn",
  healthy: "ok",
  rotating: "warn",
  stopped: "plain",
  quarantined: "bad",
  failed: "bad",
  destroyed: "plain",
};

/** Decoy state as a tag. The word carries the meaning; colour only repeats it. */
export function DecoyStateTag({ state }: { state: DecoyState }) {
  return <span className={`tag tag--${DECOY_TONE[state] ?? "plain"}`}>{state}</span>;
}

const ATTEMPT_TONE: Record<AttemptState, "plain" | "warn" | "bad"> = {
  probe: "plain",
  exploit: "warn",
  "post-exploitation": "bad",
};

export function AttemptStateTag({ state }: { state: AttemptState }) {
  return <span className={`tag tag--${ATTEMPT_TONE[state] ?? "plain"}`}>{state}</span>;
}

/** States in which a decoy is still coming up or changing, so its page keeps refreshing. */
export const SETTLING: ReadonlySet<DecoyState> = new Set(["pending", "starting", "rotating"]);

/**
 * Reason code and text, required by the API for every destructive action
 * (docs/rotation.md). Both are written to the audit log.
 */
export function ReasonFields({ idPrefix }: { idPrefix?: string }) {
  const base = useId();
  const id = idPrefix ?? base;
  return (
    <fieldset className="fieldset">
      <legend>Reason (audited)</legend>
      <div className="field">
        <label htmlFor={`${id}-code`}>Reason code</label>
        <select id={`${id}-code`} name="reason_code" defaultValue="operator_manual" required>
          {Object.entries(REASON_LABEL).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>
      <div className="field field--wide">
        <label htmlFor={`${id}-text`}>Reason text</label>
        <textarea
          id={`${id}-text`}
          name="reason_text"
          required
          minLength={1}
          maxLength={500}
          rows={2}
        />
      </div>
    </fieldset>
  );
}

/** Submit button that says it is working while its form is in flight. */
export function SubmitButton({
  children,
  intent,
  tone = "default",
  name = "intent",
}: {
  children: ReactNode;
  /** Value sent as `intent`, so one action can serve several forms. */
  intent?: string;
  tone?: "default" | "primary" | "danger";
  name?: string;
}) {
  const navigation = useNavigation();
  const mine =
    navigation.state === "submitting" &&
    (intent === undefined || navigation.formData?.get(name) === intent);
  return (
    <button
      type="submit"
      className={tone === "default" ? "btn" : `btn btn--${tone}`}
      name={intent === undefined ? undefined : name}
      value={intent}
      disabled={mine}
      aria-disabled={mine || undefined}
    >
      {mine ? "Working..." : children}
    </button>
  );
}

/** Label and value pairs. */
export function Facts({ items }: { items: readonly [string, ReactNode][] }) {
  return (
    <dl className="facts">
      {items.map(([k, v]) => (
        <div key={k} className="facts__row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Page title row. */
export function PageHead({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      <h1 className="page-head__title">{title}</h1>
      {children ? <div className="page-head__meta">{children}</div> : null}
    </header>
  );
}

/** Numbered wizard steps with the current one marked for assistive tech. */
export function WizardSteps({ steps, current }: { steps: readonly string[]; current: number }) {
  return (
    <ol className="wizard-steps" aria-label="Launch steps">
      {steps.map((s, i) => (
        <li
          key={s}
          className={
            i === current ? "wizard-steps__step wizard-steps__step--on" : "wizard-steps__step"
          }
          aria-current={i === current ? "step" : undefined}
        >
          <span className="mono">{i + 1}</span> {s}
          {i < current ? <span className="sr-only"> (done)</span> : null}
        </li>
      ))}
    </ol>
  );
}

/** A time: readable UTC text (`YYYY-MM-DD HH:MM`) plus a machine value. */
export function Time({ ms }: { ms: number | null | undefined }) {
  const text = formatTs(ms);
  if (ms === null || ms === undefined || text === "") return <span className="muted">n/a</span>;
  return <time dateTime={isoTs(ms)}>{text}</time>;
}

/** The second reviewer's write-up checklist (#35). Every box must be ticked to approve. */
export function ChecklistFields() {
  return (
    <fieldset className="fieldset field--wide">
      <legend>Second reviewer checklist (all required to approve)</legend>
      {CHECKLIST.map((c) => (
        <label key={c.key} className="check">
          <input type="checkbox" name={`check_${c.key}`} value="yes" /> {c.label}
        </label>
      ))}
    </fieldset>
  );
}
