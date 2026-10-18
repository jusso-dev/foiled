import { describe, expect, it } from "vitest";
import { agents } from "../test/fixtures";
import { ADMIN, envWith, expectPage, fakeApi, page, signIn, text } from "../test/harness";

function api() {
  return fakeApi((c) => {
    if (c.path === "/v0/hosts" && c.method === "GET")
      return { items: [agents.host], next_cursor: null };
    if (c.path === "/v0/sensors" && c.method === "GET") {
      return { items: [agents.sensor, agents.revoked], next_cursor: null };
    }
    if (c.path === "/v0/sensors" && c.method === "POST") {
      return {
        agent: { ...agents.sensor, id: "sen-0009", status: "pending" },
        enrolment: { token: `foe_sen9.${"s".repeat(40)}`, expires_at: Date.now() + 3600_000 },
      };
    }
    if (c.path.endsWith(":revoke"))
      return { agent: { ...agents.sensor, status: "revoked" }, ca_revoked: 1, ca_failed: 1 };
    return undefined;
  });
}

describe("hosts and sensors", () => {
  it("lists hosts and sensors with their status", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(api()), "/registry", { cookie }));
    const t = text(r.html);
    expect(t).toContain("Sandbox hosts");
    expect(t).toContain("Branch office emulation sensor");
    expect(t).toContain("emulations only");
    expect(t).toContain("revoked");
  });

  it("registers a sensor and shows the enrolment token once", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), "/registry", {
        cookie,
        form: {
          csrf: session.csrf,
          intent: "register",
          role: "sensors",
          label: "lab",
          enrolment_ttl_seconds: "900",
        },
      }),
    );
    const post = a.calls.find((c) => c.method === "POST");
    expect(post?.body).toEqual({
      label: "lab",
      sandbox_allowed: false,
      enrolment_ttl_seconds: 900,
    });
    expect(text(r.html)).toContain(`foe_sen9.${"s".repeat(40)}`);
    expect(text(r.html)).toContain("It is shown once.");
    // A plain reload does not show it again.
    const again = expectPage(await page(envWith(api()), "/registry", { cookie }));
    expect(again.html).not.toContain("foe_sen9");
  });

  it("revokes only with a reason and an explicit confirmation", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const form = {
      csrf: session.csrf,
      intent: "revoke",
      role: "sensors",
      agent_id: "sen-0001",
      reason_code: "operator_manual",
      reason_text: "decommissioned",
    };
    const no = expectPage(await page(envWith(a), "/registry", { cookie, form }));
    expect(no.actionData).toMatchObject({
      ok: false,
      message: "Tick the box: revocation is final.",
    });
    const yes = expectPage(
      await page(envWith(a), "/registry", { cookie, form: { ...form, confirm_revoke: "yes" } }),
    );
    expect(a.calls.find((c) => c.method === "POST")?.path).toBe("/v0/sensors/sen-0001:revoke");
    expect(text(yes.html)).toContain("finish those in the Cloudflare dashboard");
  });

  it("hides write controls from read-only tokens", async () => {
    const { cookie } = await signIn({ ...ADMIN, scopes: ["hosts:read", "sensors:read"] });
    const r = expectPage(await page(envWith(api()), "/registry", { cookie }));
    expect(text(r.html)).not.toContain("Register sensor");
    expect(text(r.html)).not.toContain("Re-enrol or revoke");
  });
});
