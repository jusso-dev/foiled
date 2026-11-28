/**
 * Destructive agent actions waiting for a human (#95), on the review queue
 * page, against the API's golden output in testdata/pending-actions/.
 */

import { describe, expect, it } from "vitest";
import type { PendingAction } from "../lib/api-types";
import { HOSTILE, pendingDestroy, pendingExecuted, reviewItem } from "../test/fixtures";
import {
  ADMIN,
  type ApiCall,
  apiError,
  envWith,
  expectPage,
  fakeApi,
  page,
  signIn,
  text,
} from "../test/harness";

const PA = pendingDestroy.id;

function api(pending: PendingAction[] = [pendingDestroy], extra?: (c: ApiCall) => unknown) {
  return fakeApi((c) => {
    const hit = extra?.(c);
    if (hit !== undefined) return hit;
    if (c.path === "/v0/review-queue") {
      return { items: [reviewItem], total: 1, truncated: false, notes: [] };
    }
    if (c.path === "/v0/pending-actions") return { items: pending, next_cursor: null };
    if (c.path === `/v0/pending-actions/${PA}/approve`) return pendingExecuted;
    if (c.path === `/v0/pending-actions/${PA}/reject`) {
      return { ...pendingDestroy, status: "rejected", decided_by: "tok1", note: "not mine" };
    }
    return undefined;
  });
}

describe("pending agent actions on the review queue", () => {
  it("lists actions waiting for a human, with the agent and its reason as data", async () => {
    const { cookie } = await signIn();
    const hostile = { ...pendingDestroy, reason: { ...pendingDestroy.reason, text: HOSTILE } };
    const a = api([hostile]);
    const r = expectPage(await page(envWith(a), "/review", { cookie }));
    const list = a.calls.find((c) => c.path === "/v0/pending-actions");
    expect(list?.search.get("status")).toBe("pending");
    const t = text(r.html);
    expect(t).toContain("Agent actions waiting for approval");
    expect(t).toContain(`Destroy sandbox ${pendingDestroy.sandbox_id}`);
    expect(t).toContain(`Asked by agent token ${pendingDestroy.requested_by}`);
    expect(t).toContain("Nothing has run.");
    expect(t).toContain("expires 15 minutes after");
    expect(r.html).toContain('value="approve_pending"');
    expect(r.html).toContain('value="reject_pending"');
    // The agent's reason is shown as inert text.
    expect(r.html).not.toContain("<img src=x");
    expect(r.html).not.toContain("‮");
    // The review queue itself still renders.
    expect(t).toContain("CVE link");
  });

  it("approves with the operator's token and says it ran once", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: { csrf: session.csrf, intent: "approve_pending", pending_id: PA, note: "I asked" },
      }),
    );
    const post = a.calls.find((c) => c.method === "POST");
    expect(post?.path).toBe(`/v0/pending-actions/${PA}/approve`);
    expect(post?.body).toEqual({ note: "I asked" });
    expect(post?.headers.get("authorization")).toMatch(/^Bearer fo_tok1\./);
    expect(r.actionData).toMatchObject({
      ok: true,
      message: `Approved. The destroy is queued as job ${pendingExecuted.job_id}. The decision is in the audit log.`,
    });
  });

  it("needs a note to reject, then rejects", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const base = { csrf: session.csrf, intent: "reject_pending", pending_id: PA };
    const r1 = expectPage(
      await page(envWith(a), "/review", { cookie, form: { ...base, note: "" } }),
    );
    expect(r1.actionData).toMatchObject({
      ok: false,
      message: "Add a note: a rejection needs a reason.",
    });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
    const r2 = expectPage(
      await page(envWith(a), "/review", { cookie, form: { ...base, note: "not mine" } }),
    );
    expect(a.calls.find((c) => c.method === "POST")?.path).toBe(`/v0/pending-actions/${PA}/reject`);
    expect(r2.actionData).toMatchObject({ ok: true });
    expect((r2.actionData as { message: string }).message).toContain(
      "Rejected. The destroy will not run.",
    );
  });

  it("shows a 409 when the action expired or someone else decided it", async () => {
    const { cookie, session } = await signIn();
    const a = api(undefined, (c) =>
      c.method === "POST"
        ? apiError(409, "conflict", "pending action is expired, not pending")
        : undefined,
    );
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: { csrf: session.csrf, intent: "approve_pending", pending_id: PA },
      }),
    );
    expect(r.actionData).toMatchObject({ ok: false });
    expect((r.actionData as { message: string }).message).toContain("expired, not pending");
  });

  it("refuses malformed ids before calling the API", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: { csrf: session.csrf, intent: "approve_pending", pending_id: "../audit" },
      }),
    );
    expect(r.actionData).toMatchObject({ ok: false, message: "Unknown pending action." });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("pages through more pending actions, keeping the pending filter", async () => {
    const { cookie } = await signIn();
    const older = { ...pendingDestroy, id: "pa_older" };
    const a = fakeApi((c) => {
      if (c.path === "/v0/review-queue") {
        return { items: [reviewItem], total: 1, truncated: false, notes: [] };
      }
      if (c.path === "/v0/pending-actions") {
        return c.search.get("cursor") === PA
          ? { items: [older], next_cursor: null }
          : { items: [pendingDestroy], next_cursor: PA };
      }
      return undefined;
    });
    const first = expectPage(await page(envWith(a), "/review?kind=cve_link", { cookie }));
    const href = `/review?kind=cve_link&amp;pending_cursor=${PA}`;
    expect(first.html).toContain(href);
    expect(text(first.html)).toContain("Older pending actions");

    const second = expectPage(
      await page(envWith(a), `/review?kind=cve_link&pending_cursor=${PA}`, { cookie }),
    );
    const call = a.calls.filter((c) => c.path === "/v0/pending-actions").at(-1);
    expect(call?.search.get("cursor")).toBe(PA);
    expect(call?.search.get("status")).toBe("pending");
    expect(text(second.html)).toContain("pa_older");
    expect(text(second.html)).not.toContain("Older pending actions");

    // A malformed cursor is dropped, not sent.
    await page(envWith(a), "/review?pending_cursor=../audit", { cookie });
    const bad = a.calls.filter((c) => c.path === "/v0/pending-actions").at(-1);
    expect(bad?.search.get("cursor")).toBeNull();
  });

  it("hides the approve buttons without decoys:write and the panel when nothing waits", async () => {
    const ro = await signIn({ ...ADMIN, scopes: ["decoys:read", "review:read"] });
    const r = expectPage(await page(envWith(api()), "/review", { cookie: ro.cookie }));
    expect(text(r.html)).toContain("Approving needs the decoys:write scope.");
    expect(r.html).not.toContain('value="approve_pending"');

    const { cookie } = await signIn();
    const empty = expectPage(await page(envWith(api([])), "/review", { cookie }));
    expect(text(empty.html)).not.toContain("Agent actions waiting for approval");

    // Without decoys:read the list is not even asked for.
    const none = await signIn({ ...ADMIN, scopes: ["review:read"] });
    const a = api();
    expectPage(await page(envWith(a), "/review", { cookie: none.cookie }));
    expect(a.calls.some((c) => c.path === "/v0/pending-actions")).toBe(false);
  });
});
