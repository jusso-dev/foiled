import { describe, expect, it } from "vitest";
import type { Principal } from "../lib/api-types";
import { agents, catalogue, decoy } from "../test/fixtures";
import {
  ADMIN,
  type ApiCall,
  apiError,
  envWith,
  expectPage,
  expectRedirect,
  fakeApi,
  page,
  signIn,
  text,
} from "../test/harness";

function api(extra?: (c: ApiCall) => unknown) {
  return fakeApi((c) => {
    const hit = extra?.(c);
    if (hit !== undefined) return hit;
    if (c.path === "/v0/catalogue/entries") {
      const kind = c.search.get("decoy_kind");
      return { items: Object.values(catalogue).filter((e) => !kind || e.decoy_kind === kind) };
    }
    if (c.path.startsWith("/v0/catalogue/entries/")) {
      const id = c.path.slice("/v0/catalogue/entries/".length);
      return (
        Object.values(catalogue).find((e) => e.id === id) ??
        apiError(404, "not_found", "entry not found")
      );
    }
    if (c.path === "/v0/sensors")
      return { items: [agents.sensor, agents.revoked], next_cursor: null };
    if (c.path === "/v0/audit") return { items: [], next_cursor: null };
    if (c.path === "/v0/decoys" && c.method === "POST") {
      return {
        decoy: decoy({ catalogue_id: (c.body as { catalogue_id: string }).catalogue_id }),
        job_id: "job-1",
        job_kind: "decoy.create",
      };
    }
    return undefined;
  });
}

const CONFIRM_SSL =
  "/launch?entry=emulator/ssl-vpn/portal-generic&step=confirm&lifetime=3600&placement=sensor&sensor=sen-0001&label=edge+vpn";

describe("launch wizard", () => {
  it("lists sandbox and emulation entries and hides drafts until asked", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(api()), "/launch", { cookie }));
    const t = text(r.html);
    expect(t).toContain("Foiled demo app");
    expect(t).toContain("ExampleVPN portal");
    expect(t).not.toContain("Redis 7.0.11");
    expect(t).toContain("1 CVE claim (critical)");
    const drafts = expectPage(await page(envWith(api()), "/launch?drafts=yes", { cookie }));
    expect(text(drafts.html)).toContain("Redis");
  });

  it("passes the kind filter to the API", async () => {
    const { cookie } = await signIn();
    const a = api();
    const r = expectPage(await page(envWith(a), "/launch?kind=emulation", { cookie }));
    expect(a.calls.find((c) => c.path === "/v0/catalogue/entries")?.search.get("decoy_kind")).toBe(
      "emulation",
    );
    expect(text(r.html)).not.toContain("Foiled demo app");
  });

  it("shows risk notes and only offers sensors that can take a sandbox entry", async () => {
    const { cookie } = await signIn();
    const r = expectPage(
      await page(envWith(api()), "/launch?entry=foiled/demo-app/1.0.0", { cookie }),
    );
    const t = text(r.html);
    expect(t).toContain("Risk notes");
    expect(t).toContain("Deliberately vulnerable synthetic app");
    expect(t).toContain("Runs the real, vulnerable software");
    // Catalogue CVE claims are labelled as claims, never as a confidence chip.
    expect(t).toContain("not links to any attempt");
    expect(r.html).not.toContain("cve-ref");
    expect(r.html.replace(/<!-- -->/g, "")).toMatch(
      /<option value="sen-0001" disabled="">[^<]*does not allow sandboxes/,
    );
  });

  it("explains a bad sensor choice before the confirm step", async () => {
    const { cookie } = await signIn();
    const r = expectPage(
      await page(
        envWith(api()),
        "/launch?entry=foiled/demo-app/1.0.0&step=confirm&placement=sensor&sensor=sen-0001",
        { cookie },
      ),
    );
    expect(text(r.html)).toContain("That sensor does not allow sandboxes.");
    expect(text(r.html)).not.toContain("Confirm launch");
  });

  it("confirms with the settings, the risk notes and where the launch is audited", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(api()), CONFIRM_SSL, { cookie }));
    const t = text(r.html);
    expect(t).toContain("Confirm launch");
    expect(t).toContain("1 hour");
    expect(t).toContain("Branch office emulation sensor (sen-0001)");
    expect(t).toContain("Launching writes decoy.create to the audit log as tok1 in tenant t1");
    expect(t).toContain("Login page emulation only.");
    expect(r.html).toMatch(/name="idempotency_key" value="[A-Za-z0-9_-]{43}"/);
  });

  const launchForm = (csrf: string, extra: Record<string, string> = {}) => ({
    csrf,
    entry: "emulator/ssl-vpn/portal-generic",
    label: "edge vpn",
    lifetime: "3600",
    placement: "sensor",
    sensor: "sen-0001",
    allow_draft: "",
    idempotency_key: "k".repeat(43),
    risk_ack: "yes",
    ...extra,
  });

  it("creates the decoy with an idempotency key and goes to its status page", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const r = await page(envWith(a), CONFIRM_SSL, { cookie, form: launchForm(session.csrf) });
    expect(expectRedirect(r)).toBe("/decoys/dcy-0001?launched=1");
    const create = a.calls.find((c) => c.method === "POST" && c.path === "/v0/decoys");
    expect(create?.body).toEqual({
      catalogue_id: "emulator/ssl-vpn/portal-generic",
      lifetime_seconds: 3600,
      label: "edge vpn",
      sensor_id: "sen-0001",
    });
    expect(create?.headers.get("idempotency-key")).toBe("k".repeat(43));
    expect(create?.headers.get("authorization")).toMatch(/^Bearer fo_tok1\./);
  });

  it("needs the risk notes acknowledged", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), CONFIRM_SSL, {
        cookie,
        form: launchForm(session.csrf, { risk_ack: "" }),
      }),
    );
    expect(text(r.html)).toContain("Confirm that you have read the risk notes.");
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("refuses a draft launch without decoys:elevate before calling the API", async () => {
    const reader: Principal = {
      ...ADMIN,
      scopes: ["catalogue:read", "decoys:read", "decoys:write", "sensors:read"],
    };
    const { cookie, session } = await signIn(reader);
    const a = api();
    const r = expectPage(
      await page(envWith(a), "/launch?entry=emulator/redis/7.0&step=confirm", {
        cookie,
        form: launchForm(session.csrf, {
          entry: "emulator/redis/7.0",
          placement: "pool",
          sensor: "",
          allow_draft: "yes",
        }),
      }),
    );
    expect(text(r.html)).toContain("Draft entries need the decoys:elevate scope.");
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("shows the API's refusal next to the form", async () => {
    const { cookie, session } = await signIn();
    const a = api((c) =>
      c.method === "POST" ? apiError(409, "conflict", "tenant has 5 live decoys") : undefined,
    );
    const r = expectPage(
      await page(envWith(a), CONFIRM_SSL, { cookie, form: launchForm(session.csrf) }),
    );
    expect(text(r.html)).toContain(
      "The current state does not allow this. tenant has 5 live decoys",
    );
  });

  it("refuses a launch without the CSRF token", async () => {
    const { cookie } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), CONFIRM_SSL, { cookie, form: launchForm("forged") }),
    );
    expect(r.status).toBe(403);
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });
});
