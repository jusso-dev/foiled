import { describe, expect, it } from "vitest";
import { decoy } from "../test/fixtures";
import { ADMIN, apiError, envWith, expectPage, fakeApi, page, signIn, text } from "../test/harness";

const audit = {
  items: [
    {
      id: "aud1",
      ts: 1792285000000,
      tenant_id: "t1",
      actor_id: "tok1",
      actor_kind: "human",
      action: "decoy.create",
      target: "dcy-0001",
      outcome: "accepted",
    },
  ],
  next_cursor: null,
};

describe("decoy status and teardown", () => {
  it("shows a launched decoy as pending, keeps refreshing and shows its audit trail", async () => {
    const { cookie } = await signIn();
    const api = fakeApi((c) => {
      if (c.path === "/v0/decoys/dcy-0001") return decoy();
      if (c.path === "/v0/audit") return audit;
      return undefined;
    });
    const r = expectPage(await page(envWith(api), "/decoys/dcy-0001?launched=1", { cookie }));
    const t = text(r.html);
    expect(t).toContain("Launch accepted");
    expect(t).toContain("this page refreshes every 5 seconds until the decoy settles");
    expect(t).toContain("decoy.create");
    expect(api.calls.find((c) => c.path === "/v0/audit")?.search.get("target")).toBe("dcy-0001");
  });

  it("stops refreshing once healthy", async () => {
    const { cookie } = await signIn();
    const api = fakeApi((c) =>
      c.path === "/v0/decoys/dcy-0001" ? decoy({ state: "healthy" }) : audit,
    );
    const r = expectPage(await page(envWith(api), "/decoys/dcy-0001", { cookie }));
    expect(text(r.html)).not.toContain("refreshes every");
    expect(r.html).toContain("tag--ok");
  });

  it("tears down with a reason, an idempotency key and an explicit confirmation", async () => {
    const { cookie, session } = await signIn();
    const api = fakeApi((c) => {
      if (c.method === "POST") {
        return { decoy: decoy({ state: "healthy" }), job_id: "job-9", job_kind: "decoy.destroy" };
      }
      if (c.path === "/v0/decoys/dcy-0001") return decoy({ state: "healthy" });
      return audit;
    });
    const form = {
      csrf: session.csrf,
      intent: "destroy",
      reason_code: "operator_manual",
      reason_text: "end of exercise",
      idempotency_key: "k".repeat(43),
    };
    const refused = expectPage(await page(envWith(api), "/decoys/dcy-0001", { cookie, form }));
    expect(text(refused.html)).toContain("Tick the box to confirm the teardown.");
    expect(api.calls.some((c) => c.method === "POST")).toBe(false);

    const r = expectPage(
      await page(envWith(api), "/decoys/dcy-0001", {
        cookie,
        form: { ...form, confirm_destroy: "yes" },
      }),
    );
    const post = api.calls.find((c) => c.method === "POST");
    expect(post?.path).toBe("/v0/decoys/dcy-0001:destroy");
    expect(post?.body).toEqual({ reason: { code: "operator_manual", text: "end of exercise" } });
    expect(post?.headers.get("idempotency-key")).toBe(`${"k".repeat(43)}-destroy`);
    expect(text(r.html)).toContain("Queued decoy.destroy as job job-9");
  });

  it("needs a reason for every action", async () => {
    const { cookie, session } = await signIn();
    const api = fakeApi((c) => (c.path === "/v0/decoys/dcy-0001" ? decoy() : audit));
    const r = expectPage(
      await page(envWith(api), "/decoys/dcy-0001", {
        cookie,
        form: {
          csrf: session.csrf,
          intent: "reset",
          reason_code: "operator_manual",
          reason_text: "",
        },
      }),
    );
    expect(text(r.html)).toContain("A reason code and text are required.");
  });

  it("hides actions from a read-only token", async () => {
    const { cookie } = await signIn({ ...ADMIN, scopes: ["decoys:read"] });
    const api = fakeApi((c) =>
      c.path === "/v0/decoys/dcy-0001"
        ? decoy()
        : apiError(403, "forbidden", "requires scope audit:read"),
    );
    const r = expectPage(await page(envWith(api), "/decoys/dcy-0001", { cookie }));
    const t = text(r.html);
    expect(t).toContain("Your token does not have decoys:write.");
    expect(t).toContain("Your token does not have the scope for this.");
  });

  it("treats another tenant's decoy as not found", async () => {
    const { cookie } = await signIn();
    const api = fakeApi(() => apiError(404, "not_found", "decoy not found"));
    const r = expectPage(await page(envWith(api), "/decoys/dcy-other", { cookie }));
    expect(r.status).toBe(404);
    expect(text(r.html)).toContain("Not found, or not visible to your tenant.");
    // The shell stays, so the operator can navigate away.
    expect(text(r.html)).toContain("Hosts and sensors");
  });

  it("never sends a crafted id to another API route", async () => {
    const { cookie } = await signIn();
    const api = fakeApi(() => decoy());
    const r = expectPage(await page(envWith(api), "/decoys/..%2Faudit", { cookie }));
    expect(r.status).toBe(404);
    expect(api.calls.every((c) => !c.path.startsWith("/v0/audit"))).toBe(true);
  });

  it("lists decoys with an empty state", async () => {
    const { cookie } = await signIn();
    const api = fakeApi(() => ({ items: [], next_cursor: null }));
    const r = expectPage(await page(envWith(api), "/decoys", { cookie }));
    expect(text(r.html)).toContain("No decoys match.");
    expect(api.calls[0].search.get("live")).toBe("true");
  });
});
