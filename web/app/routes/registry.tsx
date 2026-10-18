import { useId } from "react";
import { Form } from "react-router";
import { CsrfField } from "../components/console/ConsoleShell";
import { PageHead, ReasonFields, SubmitButton, Time } from "../components/console/Controls";
import { ActionNotice, EmptyState, ErrorState, Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import type { AgentRecord, ReasonCode } from "../lib/api-types";
import {
  field,
  intField,
  load,
  oneOf,
  requireMutation,
  requireOperator,
} from "../lib/console.server";
import { isId } from "../lib/ids";
import { middleEllipsis, toPrintable } from "../lib/printable";
import { REASON_CODES } from "../lib/reasons";
import type { Route } from "./+types/registry";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Hosts and sensors · Foiled console" }];
}

type Role = "hosts" | "sensors";
const ROLES: readonly Role[] = ["hosts", "sensors"];

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const [hosts, sensors] = await Promise.all([
    load(args.request, op.api.listAgents("hosts", { limit: 200 })),
    load(args.request, op.api.listAgents("sensors", { limit: 200 })),
  ]);
  return {
    hosts,
    sensors,
    can: { hosts: op.can("hosts:write"), sensors: op.can("sensors:write") },
  };
}

export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const f = op.form;
  const intent = oneOf(f, "intent", ["register", "revoke", "reenrol"] as const);
  const role = oneOf(f, "role", ROLES);
  const fail = (message: string) => ({
    intent: intent ?? "",
    role: role ?? "",
    ok: false,
    message,
    token: null,
  });
  if (!intent || !role) return fail("Unknown action.");
  if (intent === "register") {
    const label = field(f, "label", 100);
    const ttl = intField(f, "enrolment_ttl_seconds", 300, 86400) ?? 3600;
    const res = await load(
      args.request,
      op.api.registerAgent(role, {
        label,
        sandbox_allowed: f.get("sandbox_allowed") === "yes",
        enrolment_ttl_seconds: ttl,
      }),
    );
    if (!res.ok) return fail(res.error.message);
    return {
      intent,
      role,
      ok: true,
      message: `Registered ${res.data.agent.id}. Hand this one-time enrolment token to the ${role === "hosts" ? "host" : "sensor"} over a trusted channel. It is shown once.`,
      token: {
        value: res.data.enrolment.token,
        expiresAt: res.data.enrolment.expires_at,
        agent: res.data.agent.id,
      },
    };
  }
  const agentId = f.get("agent_id");
  if (!isId("opaque", agentId)) return fail("Unknown host or sensor.");
  const code = oneOf(f, "reason_code", REASON_CODES);
  const text = field(f, "reason_text", 500);
  if (!code || !text) return fail("A reason code and text are required.");
  const reason = { code: code as ReasonCode, text };
  if (intent === "revoke") {
    if (f.get("confirm_revoke") !== "yes") return fail("Tick the box: revocation is final.");
    const res = await load(args.request, op.api.revokeAgent(role, agentId, reason));
    if (!res.ok) return fail(res.error.message);
    return {
      intent,
      role,
      ok: true,
      message:
        res.data.ca_failed > 0
          ? `Revoked ${agentId}. ${res.data.ca_failed} certificates were not revoked at the CA: finish those in the Cloudflare dashboard (fingerprints are in the audit record).`
          : `Revoked ${agentId} and ${res.data.ca_revoked} certificates.`,
      token: null,
    };
  }
  const res = await load(args.request, op.api.reenrolAgent(role, agentId, reason));
  if (!res.ok) return fail(res.error.message);
  return {
    intent,
    role,
    ok: true,
    message: `New enrolment token for ${agentId}. Redeeming it retires the current certificates at once. It is shown once.`,
    token: {
      value: res.data.enrolment.token,
      expiresAt: res.data.enrolment.expires_at,
      agent: agentId,
    },
  };
}

export default function Registry({ loaderData: d, actionData }: Route.ComponentProps) {
  return (
    <>
      <PageHead title="Hosts and sensors">
        <span className="muted">Enrol, re-enrol and revoke the agents that run your decoys.</span>
      </PageHead>
      {actionData?.token ? (
        <Notice kind="ok" title="One-time enrolment token">
          <p>{toPrintable(actionData.message)}</p>
          <p>
            <output className="token-once mono" aria-label="Enrolment token">
              {actionData.token.value}
            </output>
          </p>
          <p className="hint">
            Expires <Time ms={actionData.token.expiresAt} />. Only its hash is stored. Reloading
            this page will not show it again.
          </p>
        </Notice>
      ) : (
        <ActionNotice result={actionData} />
      )}
      <AgentSection agentRole="hosts" title="Sandbox hosts" data={d.hosts} canWrite={d.can.hosts} />
      <AgentSection
        agentRole="sensors"
        title="Edge sensors"
        data={d.sensors}
        canWrite={d.can.sensors}
      />
    </>
  );
}

function AgentSection({
  agentRole: role,
  title,
  data,
  canWrite,
}: {
  agentRole: Role;
  title: string;
  data: Route.ComponentProps["loaderData"]["hosts"];
  canWrite: boolean;
}) {
  const id = useId();
  const one = role === "hosts" ? "host" : "sensor";
  return (
    <section className="card panel" aria-labelledby={`${id}-h`}>
      <header className="panel__head">
        <h2 id={`${id}-h`} className="panel__title">
          {title}
        </h2>
      </header>
      {!data.ok ? <ErrorState what={title} error={data.error} /> : null}
      {data.ok && data.data.items.length === 0 ? (
        <EmptyState>
          <p>No {role} registered yet.</p>
        </EmptyState>
      ) : null}
      {data.ok && data.data.items.length ? (
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">{title}</caption>
            <thead>
              <tr>
                <th scope="col">Id</th>
                <th scope="col">Label</th>
                <th scope="col">Status</th>
                <th scope="col">Sandboxes</th>
                <th scope="col">Last seen</th>
                <th scope="col">Certificate</th>
                <th scope="col">Network</th>
                {canWrite ? <th scope="col">Actions</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.data.items.map((a) => (
                <AgentRow key={a.id} agent={a} agentRole={role} canWrite={canWrite} />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {canWrite ? (
        <Form method="post" className="form-grid panel__body" aria-label={`Register a ${one}`}>
          <CsrfField />
          <input type="hidden" name="role" value={role} />
          <div className="field">
            <label htmlFor={`${id}-label`}>Label</label>
            <input id={`${id}-label`} name="label" maxLength={100} />
          </div>
          <div className="field">
            <label htmlFor={`${id}-ttl`}>Token lifetime</label>
            <select id={`${id}-ttl`} name="enrolment_ttl_seconds" defaultValue="3600">
              <option value="900">15 minutes</option>
              <option value="3600">1 hour (default)</option>
              <option value="86400">24 hours</option>
            </select>
          </div>
          <label className="check">
            <input
              type="checkbox"
              name="sandbox_allowed"
              value="yes"
              defaultChecked={role === "hosts"}
            />{" "}
            Allow sandbox decoys {role === "sensors" ? "(off by default for edge sensors)" : ""}
          </label>
          <SubmitButton intent="register" tone="primary">
            Register {one}
          </SubmitButton>
        </Form>
      ) : null}
    </section>
  );
}

function AgentRow({
  agent: a,
  agentRole: role,
  canWrite,
}: {
  agent: AgentRecord;
  agentRole: Role;
  canWrite: boolean;
}) {
  const id = useId();
  return (
    <tr>
      <td className="mono">{toPrintable(a.id)}</td>
      <td className="wrap">
        {a.label ? toPrintable(a.label) : <span className="muted">none</span>}
      </td>
      <td>
        <span
          className={
            a.status === "active"
              ? "tag tag--ok"
              : a.status === "revoked"
                ? "tag tag--bad"
                : "tag tag--warn"
          }
        >
          {a.status}
        </span>
      </td>
      <td>{a.sandbox_allowed ? "allowed" : "emulations only"}</td>
      <td className="mono muted">
        <Time ms={a.last_seen_at} />
      </td>
      <td className="mono muted">
        {a.cert_sha256 ? (
          <span title={a.cert_sha256}>
            {middleEllipsis(a.cert_sha256, 16)} until <Time ms={a.cert_expires_at} />
          </span>
        ) : (
          "none"
        )}
      </td>
      <td className="mono muted">
        {a.last_ip ? toPrintable(a.last_ip) : "n/a"}
        {a.last_asn ? ` AS${a.last_asn}` : ""}
        {a.network_changed_at ? <span className="tag tag--warn"> moved</span> : null}
      </td>
      {canWrite ? (
        <td>
          {a.status === "revoked" ? (
            <span className="muted">
              Revoked <Time ms={a.revoked_at} />
            </span>
          ) : (
            <details className="row-actions">
              <summary className="link">Re-enrol or revoke</summary>
              <Form method="post" className="form-grid">
                <CsrfField />
                <input type="hidden" name="role" value={role} />
                <input type="hidden" name="agent_id" value={a.id} />
                <ReasonFields idPrefix={`${id}-reason`} />
                <label className="check field--wide">
                  <input type="checkbox" name="confirm_revoke" value="yes" /> Revocation is final
                  (needed for Revoke only)
                </label>
                <div className="actions-row field--wide">
                  <SubmitButton intent="reenrol">Re-enrol</SubmitButton>
                  <SubmitButton intent="revoke" tone="danger">
                    Revoke
                  </SubmitButton>
                </div>
              </Form>
            </details>
          )}
        </td>
      ) : null}
    </tr>
  );
}

export function ErrorBoundary() {
  return <RouteError what="Hosts and sensors" />;
}
