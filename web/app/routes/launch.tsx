import { useId } from "react";
import { Form, Link, redirect } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import { Facts, PageHead, SubmitButton, Time, WizardSteps } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { AgentRecord, CatalogueEntry } from "../lib/api-types";
import { load, must, requireMutation, requireOperator } from "../lib/console.server";
import { isId } from "../lib/ids";
import {
  checkLaunch,
  configQuery,
  createBody,
  DEFAULT_LIFETIME,
  KIND_NOTE,
  LIFETIMES,
  lifetimeLabel,
  sensorFits,
} from "../lib/launch";
import { toPrintable } from "../lib/printable";
import { randomToken } from "../lib/session.server";
import type { Route } from "./+types/launch";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Launch a decoy · Foiled console" }];
}

const STEPS = ["Choose an entry", "Placement and lifetime", "Confirm"] as const;

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const { request } = args;
  const params = new URL(request.url).searchParams;
  const entryId = params.get("entry");
  const canLaunch = op.can("decoys:write");
  const canElevate = op.can("decoys:elevate");
  const who = { id: op.session.principal.id, tenant: op.session.principal.tenant_id };

  if (!entryId) {
    const kind = params.get("kind");
    const decoyKind = kind === "sandbox" || kind === "emulation" ? kind : undefined;
    const cve = params.get("cve")?.trim().slice(0, 64) || undefined;
    const drafts = params.get("drafts") === "yes";
    const list = await load(request, op.api.listCatalogue({ decoy_kind: decoyKind, cve }));
    return {
      step: 0 as const,
      filters: { kind: decoyKind ?? "all", cve: cve ?? "", drafts },
      entries: list.ok
        ? list.data.items.filter((e) => drafts || e.status !== "draft")
        : ([] as CatalogueEntry[]),
      error: list.ok ? null : list.error,
      canLaunch,
      who,
    };
  }

  if (!isId("catalogue", entryId)) {
    throw new Response(null, { status: 404, statusText: "Not found" });
  }
  const entry = await must(request, op.api.getCatalogueEntry(entryId));
  const sensorsRes = await load(request, op.api.listAgents("sensors", { limit: 200 }));
  const sensors = sensorsRes.ok ? sensorsRes.data.items : ([] as AgentRecord[]);
  const confirm = params.get("step") === "confirm";
  const check = checkLaunch(params, entry, sensors, canElevate);
  const showConfirm = confirm && Object.keys(check.errors).length === 0;
  const recent = showConfirm
    ? await load(request, op.api.listAudit({ action: "decoy.create", limit: 5 }))
    : null;
  return {
    step: (showConfirm ? 2 : 1) as 1 | 2,
    entry,
    sensors,
    sensorsError: sensorsRes.ok ? null : sensorsRes.error,
    config: check.config,
    // Only show errors once the operator has asked to review.
    errors: confirm ? check.errors : {},
    idempotencyKey: randomToken(),
    recent: recent?.ok ? recent.data.items : null,
    canLaunch,
    canElevate,
    who,
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const { form } = op;
  const { request } = args;
  const entryId = form.get("entry");
  if (!isId("catalogue", entryId)) return { ok: false, message: "Unknown catalogue entry." };
  if (form.get("risk_ack") !== "yes") {
    return { ok: false, message: "Confirm that you have read the risk notes." };
  }
  const key = String(form.get("idempotency_key") ?? "");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) {
    return { ok: false, message: "This form has expired. Go back a step and confirm again." };
  }
  const entry = await load(request, op.api.getCatalogueEntry(entryId));
  if (!entry.ok) return { ok: false, message: entry.error.message };
  const sensors = await load(request, op.api.listAgents("sensors", { limit: 200 }));
  const check = checkLaunch(
    form,
    entry.data,
    sensors.ok ? sensors.data.items : [],
    op.can("decoys:elevate"),
  );
  const problems = Object.values(check.errors);
  if (problems.length) return { ok: false, message: problems.join(" ") };
  const res = await load(request, op.api.createDecoy(createBody(check.config), key));
  if (!res.ok) return { ok: false, message: res.error.message };
  return redirect(`/decoys/${encodeURIComponent(res.data.decoy.id)}?launched=1`);
}

export default function Launch({ loaderData, actionData }: Route.ComponentProps) {
  const d = loaderData;
  return (
    <>
      <PageHead title="Launch a decoy">
        <span className="muted">Sandbox and emulation entries from the reviewed catalogue.</span>
      </PageHead>
      <WizardSteps steps={STEPS} current={d.step} />
      {!d.canLaunch ? (
        <Notice kind="warn" title="Read only">
          <p>Your token does not have decoys:write, so you can browse but not launch.</p>
        </Notice>
      ) : null}
      {d.step !== 2 && actionData && !actionData.ok ? <ActionNotice result={actionData} /> : null}
      {d.step === 0 ? <ChooseEntry data={d} /> : null}
      {d.step === 1 ? <Configure data={d} /> : null}
      {d.step === 2 ? <Confirm data={d} result={actionData} /> : null}
    </>
  );
}

type Data = Route.ComponentProps["loaderData"];
type Step0 = Extract<Data, { step: 0 }>;
type StepN = Exclude<Data, { step: 0 }>;

function ChooseEntry({ data }: { data: Step0 }) {
  const id = useId();
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          Catalogue
        </h2>
      </header>
      <Form method="get" className="filters" aria-label="Filter the catalogue">
        <fieldset className="fieldset fieldset--inline">
          <legend>Decoy kind</legend>
          {(["all", "sandbox", "emulation"] as const).map((k) => (
            <label key={k} className="radio">
              <input type="radio" name="kind" value={k} defaultChecked={data.filters.kind === k} />{" "}
              {k === "all" ? "All" : k === "sandbox" ? "Sandbox" : "Emulation"}
            </label>
          ))}
        </fieldset>
        <div className="field">
          <label htmlFor={`${id}-cve`}>CVE id</label>
          <input
            id={`${id}-cve`}
            name="cve"
            defaultValue={data.filters.cve}
            maxLength={64}
            placeholder="CVE-2099-0001"
          />
        </div>
        <label className="check">
          <input type="checkbox" name="drafts" value="yes" defaultChecked={data.filters.drafts} />{" "}
          Include draft entries
        </label>
        <button type="submit" className="btn">
          Apply
        </button>
      </Form>
      {data.error ? <ErrorState what="Catalogue" error={data.error} /> : null}
      {!data.error && data.entries.length === 0 ? (
        <EmptyState>
          <p>No catalogue entries match. Clear the filters or include draft entries.</p>
        </EmptyState>
      ) : null}
      {data.entries.length ? (
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">Catalogue entries</caption>
            <thead>
              <tr>
                <th scope="col">Product</th>
                <th scope="col">Kind</th>
                <th scope="col">Status</th>
                <th scope="col">Catalogue claims</th>
                <th scope="col">Ports</th>
                <th scope="col">
                  <span className="sr-only">Choose</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.entries.map((e) => (
                <tr key={e.id}>
                  <td className="wrap">
                    <strong>{toPrintable(e.product)}</strong>{" "}
                    <span className="muted">
                      {toPrintable(e.vendor)} {toPrintable(e.version)}
                    </span>
                    <div className="mono muted">{e.id}</div>
                  </td>
                  <td>
                    <span className="tag">{e.decoy_kind}</span>
                  </td>
                  <td>
                    <span className={e.status === "verified" ? "tag tag--ok" : "tag tag--warn"}>
                      {e.status}
                    </span>
                  </td>
                  <td className="wrap">
                    {e.cves.length ? (
                      <span>
                        {`${e.cves.length} CVE ${e.cves.length === 1 ? "claim" : "claims"} (${e.cves
                          .map((c) => c.severity ?? "unrated")
                          .join(", ")})`}
                      </span>
                    ) : (
                      <span className="muted">none</span>
                    )}
                  </td>
                  <td className="mono muted">
                    {e.listen_ports.map((p) => `${p.port}/${p.protocol}`).join(", ")}
                  </td>
                  <td>
                    {e.status === "deprecated" ? (
                      <span className="muted">Deprecated</span>
                    ) : (
                      <Link className="btn" to={`/launch?entry=${encodeURIComponent(e.id)}`}>
                        Choose<span className="sr-only"> {toPrintable(e.product)}</span>
                      </Link>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

function EntrySummary({ entry }: { entry: CatalogueEntry }) {
  return (
    <section className="card panel" aria-label="Catalogue entry">
      <header className="panel__head">
        <h2 className="panel__title">
          {toPrintable(entry.product)} {toPrintable(entry.version)}
        </h2>
        <span className="tag">{entry.decoy_kind}</span>
      </header>
      <div className="panel__body">
        <p>{KIND_NOTE[entry.decoy_kind]}</p>
        <Facts
          items={[
            ["Entry", <span className="mono">{entry.id}</span>],
            ["Vendor", toPrintable(entry.vendor)],
            ["Status", entry.status],
            [
              "Ports",
              <span className="mono">
                {entry.listen_ports.map((p) => `${p.port}/${p.protocol}`).join(", ")}
              </span>,
            ],
            [
              "Expected techniques",
              entry.expected_techniques?.length ? (
                <span className="mono">
                  {entry.expected_techniques.join(", ")} (priors, not proof)
                </span>
              ) : (
                "none listed"
              ),
            ],
          ]}
        />
        <h3 className="explain__h">Catalogue claims</h3>
        {entry.cves.length ? (
          <>
            <p className="hint">
              CVEs the catalogue lists for this product. These are claims about the software, not
              links to any attempt.
            </p>
            <ul className="bullets">
              {entry.cves.map((c) => (
                <li key={c.cve_id}>
                  <span className="mono">{toPrintable(c.cve_id)}</span>{" "}
                  <span className="muted">
                    {c.severity ?? "unrated"}
                    {c.auth_requirement ? `, ${c.auth_requirement}` : ""}
                    {c.sources?.length ? `, sources: ${c.sources.join(", ")}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="muted">No CVE claims.</p>
        )}
      </div>
    </section>
  );
}

function RiskNotes({ entry }: { entry: CatalogueEntry }) {
  return (
    <section className="card panel risk" aria-label="Risk notes">
      <header className="panel__head">
        <h2 className="panel__title">Risk notes</h2>
      </header>
      <div className="panel__body">
        <p>{toPrintable(entry.risk_notes)}</p>
        {entry.status === "draft" ? (
          <p className="risk__draft">
            This entry is a draft: it has not been reviewed and tested to the verified standard.
          </p>
        ) : null}
      </div>
    </section>
  );
}

function Configure({ data }: { data: StepN }) {
  const id = useId();
  const { entry, config, errors } = data;
  const err = (k: string) =>
    errors[k] ? (
      <p id={`${id}-${k}-err`} className="field__error">
        {errors[k]}
      </p>
    ) : null;
  const described = (k: string) => (errors[k] ? `${id}-${k}-err` : undefined);
  return (
    <>
      <div className="split">
        <EntrySummary entry={entry} />
        <RiskNotes entry={entry} />
      </div>
      <section className="card panel" aria-labelledby={`${id}-h`}>
        <header className="panel__head">
          <h2 id={`${id}-h`} className="panel__title">
            Placement and lifetime
          </h2>
        </header>
        {Object.keys(errors).length ? (
          <Notice kind="error" title="Check these settings">
            <ul className="bullets">
              {Object.values(errors).map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          </Notice>
        ) : null}
        {errors.entry ? null : (
          <Form method="get" className="form-grid">
            <input type="hidden" name="entry" value={entry.id} />
            <input type="hidden" name="step" value="confirm" />
            <div className="field">
              <label htmlFor={`${id}-label`}>Label (optional)</label>
              <input
                id={`${id}-label`}
                name="label"
                maxLength={100}
                defaultValue={config.label ?? ""}
                aria-invalid={errors.label ? true : undefined}
                aria-describedby={described("label")}
              />
              {err("label")}
            </div>
            <div className="field">
              <label htmlFor={`${id}-lifetime`}>Lifetime</label>
              <select
                id={`${id}-lifetime`}
                name="lifetime"
                defaultValue={String(config.lifetime ?? DEFAULT_LIFETIME)}
                aria-describedby={`${id}-lifetime-hint`}
              >
                {LIFETIMES.map((l) => (
                  <option key={l.seconds} value={l.seconds}>
                    {l.label}
                  </option>
                ))}
              </select>
              <p id={`${id}-lifetime-hint`} className="hint">
                The decoy rotates when its lifetime ends.
              </p>
            </div>
            <fieldset className="fieldset field--wide">
              <legend>Placement</legend>
              <label className="radio">
                <input
                  type="radio"
                  name="placement"
                  value="pool"
                  defaultChecked={config.placement !== "sensor"}
                />{" "}
                Research host pool: the first research host to lease the job runs it
              </label>
              <label className="radio">
                <input
                  type="radio"
                  name="placement"
                  value="sensor"
                  defaultChecked={config.placement === "sensor"}
                />{" "}
                A specific edge sensor
              </label>
              <div className="field">
                <label htmlFor={`${id}-sensor`}>Edge sensor</label>
                <select
                  id={`${id}-sensor`}
                  name="sensor"
                  defaultValue={config.sensorId ?? ""}
                  aria-invalid={errors.sensor ? true : undefined}
                  aria-describedby={described("sensor")}
                >
                  <option value="">Choose a sensor</option>
                  {data.sensors.map((s) => {
                    const why = sensorFits(entry, s);
                    return (
                      <option key={s.id} value={s.id} disabled={why !== null}>
                        {s.label ? `${toPrintable(s.label)} (${s.id})` : s.id}
                        {s.status === "pending" ? ", not enrolled yet" : ""}
                        {why ? `, ${why}` : ""}
                      </option>
                    );
                  })}
                </select>
                {err("sensor")}
                {data.sensorsError ? (
                  <p className="hint">Sensors could not be listed: {data.sensorsError.message}</p>
                ) : null}
              </div>
            </fieldset>
            {entry.status === "draft" ? (
              <div className="field field--wide">
                <label className="check">
                  <input
                    type="checkbox"
                    name="allow_draft"
                    value="yes"
                    defaultChecked={config.allowDraft}
                    disabled={!data.canElevate}
                    aria-describedby={`${id}-draft-hint ${described("allow_draft") ?? ""}`.trim()}
                  />{" "}
                  Launch this draft entry
                </label>
                <p id={`${id}-draft-hint`} className="hint">
                  {data.canElevate
                    ? "Draft launches need decoys:elevate and are audited."
                    : "Your token does not have decoys:elevate, so draft entries cannot be launched."}
                </p>
                {err("allow_draft")}
              </div>
            ) : null}
            <div className="actions-row field--wide">
              <Link className="btn" to="/launch">
                Back to the catalogue
              </Link>
              <button type="submit" className="btn btn--primary">
                Review launch
              </button>
            </div>
          </Form>
        )}
      </section>
    </>
  );
}

function Confirm({
  data,
  result,
}: {
  data: StepN;
  result?: { ok: boolean; message: string } | null;
}) {
  const id = useId();
  const { entry, config } = data;
  const sensor = data.sensors.find((s) => s.id === config.sensorId);
  return (
    <>
      <div className="split">
        <section className="card panel" aria-labelledby={`${id}-h`}>
          <header className="panel__head">
            <h2 id={`${id}-h`} className="panel__title">
              Confirm launch
            </h2>
          </header>
          <div className="panel__body">
            <Facts
              items={[
                ["Entry", <span className="mono">{entry.id}</span>],
                ["Kind", entry.decoy_kind],
                ["Status", entry.status],
                ["Label", config.label ? toPrintable(config.label) : "none"],
                ["Lifetime", lifetimeLabel(config.lifetime)],
                [
                  "Placement",
                  config.placement === "sensor" ? (
                    <span>
                      Edge sensor{" "}
                      <span className="mono">
                        {sensor?.label
                          ? `${toPrintable(sensor.label)} (${config.sensorId})`
                          : config.sensorId}
                      </span>
                    </span>
                  ) : (
                    "Research host pool"
                  ),
                ],
                ["Egress", "Deny by default (#4)"],
              ]}
            />
            <p className="hint">
              Launching writes <span className="mono">decoy.create</span> to the{" "}
              <Link className="link" to="/audit?action=decoy.create">
                audit log
              </Link>{" "}
              as <span className="mono">{data.who.id}</span> in tenant{" "}
              <span className="mono">{data.who.tenant}</span>. The decoy stays pending until a host
              reports it healthy.
            </p>
          </div>
        </section>
        <RiskNotes entry={entry} />
      </div>
      <section className="card panel" aria-label="Launch">
        <Form method="post" className="form-grid">
          <CsrfField />
          <input type="hidden" name="entry" value={entry.id} />
          <input type="hidden" name="label" value={config.label ?? ""} />
          <input type="hidden" name="lifetime" value={config.lifetime} />
          <input type="hidden" name="placement" value={config.placement} />
          <input type="hidden" name="sensor" value={config.sensorId ?? ""} />
          <input type="hidden" name="allow_draft" value={config.allowDraft ? "yes" : ""} />
          <input type="hidden" name="idempotency_key" value={data.idempotencyKey} />
          <label className="check field--wide">
            <input type="checkbox" name="risk_ack" value="yes" required /> I have read the risk
            notes for this entry
          </label>
          <div className="actions-row field--wide">
            <Link className="btn" to={`/launch?${configQuery(config)}`}>
              Change settings
            </Link>
            {data.canLaunch ? (
              <SubmitButton tone="primary">Launch decoy</SubmitButton>
            ) : (
              <span className="muted">Your token cannot launch decoys.</span>
            )}
          </div>
          <div className="field--wide">
            <ActionNotice result={result} />
          </div>
        </Form>
      </section>
      {data.recent ? (
        <section className="card panel" aria-label="Recent launches">
          <header className="panel__head">
            <h2 className="panel__title">Recent launches (audit log)</h2>
          </header>
          {data.recent.length ? (
            <ul className="bullets panel__body">
              {data.recent.map((r) => (
                <li key={r.id}>
                  <Time ms={r.ts} /> <span className="mono">{toPrintable(r.actor_id)}</span>{" "}
                  {r.outcome} <span className="mono">{r.target ? toPrintable(r.target) : ""}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState>
              <p>No launches recorded yet.</p>
            </EmptyState>
          )}
        </section>
      ) : null}
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Launch a decoy" />;
}
