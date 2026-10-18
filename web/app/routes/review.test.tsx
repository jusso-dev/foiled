/**
 * Review queue, write-ups, radar (#35) and actor associations (#29), against
 * the API's golden output in testdata/.
 */

import { describe, expect, it } from "vitest";
import type { ReviewItem } from "../lib/api-types";
import { actorLinkRecord, radarFeed, reviewIoc, reviewItem, writeUp } from "../test/fixtures";
import {
  ADMIN,
  type ApiCall,
  apiError,
  envWith,
  expectPage,
  expectRedirect,
  fakeApi,
  notServed,
  page,
  signIn,
  text,
} from "../test/harness";

const RQ = reviewItem.item_id;

function reviewApi(items: ReviewItem[] = [reviewItem, reviewIoc], extra?: (c: ApiCall) => unknown) {
  return fakeApi((c) => {
    const hit = extra?.(c);
    if (hit !== undefined) return hit;
    if (c.path === "/v0/review-queue")
      return { items, total: items.length, truncated: false, notes: [] };
    if (c.path === `/v0/review-queue/${RQ}/actions`) {
      return {
        item: { ...reviewItem, status: "approved" },
        effect: "link override recorded",
        writeup_id: null,
      };
    }
    return undefined;
  });
}

const form = (csrf: string, extra: Record<string, string>) => ({
  csrf,
  item_id: RQ,
  kind: reviewItem.kind,
  version: String(reviewItem.version),
  ...extra,
});

describe("review queue", () => {
  it("says the queue is not served yet when the API falls through", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(fakeApi(() => notServed())), "/review", { cookie }));
    expect(text(r.html)).toContain("Review queue: not served yet");
    expect(r.html).toContain("issues/35");
  });

  it("lists pending items with their wording, SLA and subject links", async () => {
    const { cookie } = await signIn();
    const a = reviewApi();
    const r = expectPage(await page(envWith(a), "/review?overdue=yes&mine=yes", { cookie }));
    expect(a.calls[0].search.get("status")).toBe("pending");
    expect(a.calls[0].search.get("sla_breached")).toBe("true");
    expect(a.calls[0].search.get("assignee")).toBe("me");
    const t = text(r.html);
    expect(t).toContain("CVE link");
    expect(t).toContain("We assess as an attempt against FOILED-DEMO-0001. Score 98 of 100");
    expect(t).toContain("24h SLA");
    expect(t).toContain("hxxp://stage2[.]example[.]invalid");
    expect(r.html).toContain(`/attempts/${reviewItem.subject.attempt_id}`);
    expect(r.html).toContain(`/iocs/${reviewIoc.subject.ioc_id}`);
    expect(r.html).toContain('value="promote"');
  });

  it("shows stuck decisions, merge proposals and promote only where the API allows it", async () => {
    const { cookie } = await signIn();
    const A = "cmp_0123456789abcdef01234567";
    const B = "cmp_89abcdef0123456789abcdef";
    const merge: ReviewItem = {
      ...reviewItem,
      item_id: `${RQ}m`,
      kind: "campaign_merge",
      subject: { campaign_id: A, other_campaign_id: B },
      wording: "possible",
      status: "needs_attention",
    };
    const a = reviewApi([merge, reviewIoc]);
    const r = expectPage(await page(envWith(a), "/review?status=needs_attention", { cookie }));
    expect(a.calls[0].search.get("status")).toBe("needs_attention");
    const t = text(r.html);
    expect(t).toContain("Campaign merge proposal");
    expect(t).toContain("needs attention");
    expect(t).toContain("decide it again (after a minute)");
    expect(r.html).toContain(`/campaigns/${A}`);
    expect(r.html).toContain(`/campaigns/${B}`);
    expect(t).toContain(`fold ${B} into ${A}`);
    // Neither a merge proposal nor an IOC publication can start a write-up.
    expect(r.html).not.toContain('value="promote"');
  });

  it("approves with a note and the item's version", async () => {
    const { cookie, session } = await signIn();
    const a = reviewApi();
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: form(session.csrf, { intent: "approve", note: "hook fired" }),
      }),
    );
    const post = a.calls.find((c) => c.method === "POST");
    expect(post?.path).toBe(`/v0/review-queue/${RQ}/actions`);
    expect(post?.body).toEqual({ action: "approve", note: "hook fired", expected_version: 0 });
    expect(r.actionData).toMatchObject({
      ok: true,
      message: "Approved. link override recorded The action is in the audit log.",
    });
  });

  it("needs a note to reject and snoozes for at most 30 days", async () => {
    const { cookie, session } = await signIn();
    const a = reviewApi();
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: form(session.csrf, { intent: "reject", note: "" }),
      }),
    );
    expect(r.actionData).toMatchObject({
      ok: false,
      message: "Add a note: a rejection needs a reason.",
    });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
    await page(envWith(a), "/review", {
      cookie,
      form: form(session.csrf, { intent: "snooze", snooze_days: "30", note: "waiting on vendor" }),
    });
    const until = (a.calls.find((c) => c.method === "POST")?.body as { until: number } | undefined)
      ?.until;
    expect(until).toBeLessThanOrEqual(Date.now() + 30 * 24 * 3600_000);
    expect(until).toBeGreaterThan(Date.now() + 29 * 24 * 3600_000);
  });

  it("needs a note to snooze", async () => {
    const { cookie, session } = await signIn();
    const a = reviewApi();
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: form(session.csrf, { intent: "snooze", snooze_days: "7", note: "" }),
      }),
    );
    expect(r.actionData).toMatchObject({
      ok: false,
      message: "Add a note: say why you are snoozing it.",
    });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("claims and promotes to a draft write-up", async () => {
    const { cookie, session } = await signIn();
    const a = reviewApi(undefined, (c) =>
      c.method === "POST" && (c.body as { action: string }).action === "promote"
        ? { item: reviewItem, effect: null, writeup_id: writeUp.writeup_id }
        : undefined,
    );
    await page(envWith(a), "/review", { cookie, form: form(session.csrf, { intent: "claim" }) });
    expect(a.calls.find((c) => c.method === "POST")?.body).toMatchObject({ action: "claim" });
    const r = await page(envWith(a), "/review", {
      cookie,
      form: form(session.csrf, { intent: "promote" }),
    });
    expect(expectRedirect(r)).toBe(`/writeups/${writeUp.writeup_id}?promoted=1`);
  });

  it("needs the full checklist to approve a write-up item", async () => {
    const { cookie, session } = await signIn();
    const wuItem: ReviewItem = {
      ...reviewItem,
      kind: "write_up",
      subject: { writeup_id: writeUp.writeup_id },
    };
    const a = reviewApi([wuItem]);
    const page1 = expectPage(await page(envWith(a), "/review", { cookie }));
    expect(text(page1.html)).toContain("Second reviewer checklist");
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: form(session.csrf, {
          kind: "write_up",
          intent: "approve",
          check_wording_checked: "yes",
        }),
      }),
    );
    expect(r.actionData).toMatchObject({
      ok: false,
      message: "Tick every checklist item to approve.",
    });
  });

  it("shows a 409 when the item changed", async () => {
    const { cookie, session } = await signIn();
    const a = reviewApi(undefined, (c) =>
      c.method === "POST" ? apiError(409, "conflict", "item version changed") : undefined,
    );
    const r = expectPage(
      await page(envWith(a), "/review", {
        cookie,
        form: form(session.csrf, { intent: "approve", note: "n" }),
      }),
    );
    expect(r.actionData).toMatchObject({ ok: false });
    expect((r.actionData as { message: string }).message).toContain("item version changed");
  });

  it("hides decisions from tokens without review:write", async () => {
    const { cookie } = await signIn({ ...ADMIN, scopes: ["review:read"] });
    const r = expectPage(await page(envWith(reviewApi()), "/review", { cookie }));
    expect(text(r.html)).not.toContain("Approve");
  });
});

describe("write-ups", () => {
  const wuApi = (extra?: (c: ApiCall) => unknown) =>
    fakeApi((c) => {
      const hit = extra?.(c);
      if (hit !== undefined) return hit;
      if (c.path === "/v0/write-ups" && c.method === "GET") return { items: [writeUp] };
      if (c.path === "/v0/write-ups" && c.method === "POST")
        return { ...writeUp, status: "draft", version: 1 };
      if (c.path === `/v0/write-ups/${writeUp.writeup_id}/versions`) {
        return {
          writeup_id: writeUp.writeup_id,
          items: [{ writeup: writeUp, action: "create", actor_id: "tok_author", at: 1 }],
        };
      }
      if (c.path === `/v0/write-ups/${writeUp.writeup_id}`) return writeUp;
      return undefined;
    });

  it("lists write-ups and starts a draft", async () => {
    const { cookie, session } = await signIn();
    const a = wuApi();
    const list = expectPage(await page(envWith(a), "/writeups", { cookie }));
    expect(text(list.html)).toContain("Upload path traversal attempts against Demo App");
    const r = await page(envWith(a), "/writeups", {
      cookie,
      form: { csrf: session.csrf, slug: "new-draft", title: "New" },
    });
    expect(expectRedirect(r)).toBe(`/writeups/${writeUp.writeup_id}`);
    expect(a.calls.find((c) => c.method === "POST")?.body).toEqual({
      slug: "new-draft",
      title: "New",
      tlp: "amber",
    });
  });

  it("shows the Markdown as text, never as HTML", async () => {
    const { cookie } = await signIn();
    const hostile = {
      ...writeUp,
      status: "draft" as const,
      body_md: "# Hi\n<script>alert(1)</script>",
    };
    const r = expectPage(
      await page(
        envWith(
          wuApi((c) => (c.path === `/v0/write-ups/${writeUp.writeup_id}` ? hostile : undefined)),
        ),
        `/writeups/${writeUp.writeup_id}`,
        { cookie },
      ),
    );
    expect(r.html).not.toContain("<script>");
    expect(r.html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(text(r.html)).toContain("Save draft");
  });

  it("edits a draft with its version and refuses malformed CVE ids", async () => {
    const { cookie, session } = await signIn();
    const draft = { ...writeUp, status: "draft" as const };
    const a = wuApi((c) => {
      if (c.method === "PATCH") return { ...draft, version: 5, lint: [] };
      if (c.path === `/v0/write-ups/${writeUp.writeup_id}`) return draft;
      return undefined;
    });
    const base = {
      csrf: session.csrf,
      intent: "edit",
      version: "4",
      title: "T",
      tlp: "clear",
      technique_ids: "t1190",
    };
    const bad = expectPage(
      await page(envWith(a), `/writeups/${writeUp.writeup_id}`, {
        cookie,
        form: { ...base, cve_ids: "CVE-1" },
      }),
    );
    expect(bad.actionData).toMatchObject({ ok: false });
    const ok = expectPage(
      await page(envWith(a), `/writeups/${writeUp.writeup_id}`, {
        cookie,
        form: { ...base, cve_ids: "foiled-demo-0001", embargo_until: "2099-01-02" },
      }),
    );
    const patch = a.calls.find((c) => c.method === "PATCH");
    expect(patch?.body).toMatchObject({
      expected_version: 4,
      tlp: "clear",
      cve_ids: ["FOILED-DEMO-0001"],
      technique_ids: ["T1190"],
      embargo_until: Date.UTC(2099, 0, 2),
    });
    expect(ok.actionData).toMatchObject({ ok: true, message: "Saved as version 5." });
  });

  it("publishes only with review:publish and an explicit confirmation", async () => {
    const env = envWith(
      wuApi((c) => (c.method === "POST" ? { ...writeUp, status: "published" } : undefined)),
    );
    const noPublish = await signIn({ ...ADMIN, scopes: ["review:read", "review:write"] });
    const r1 = expectPage(
      await page(env, `/writeups/${writeUp.writeup_id}`, { cookie: noPublish.cookie }),
    );
    expect(text(r1.html)).not.toContain("Publish to the public site");
    const { cookie, session } = await signIn();
    const r2 = expectPage(
      await page(env, `/writeups/${writeUp.writeup_id}`, {
        cookie,
        form: { csrf: session.csrf, intent: "published", version: "4" },
      }),
    );
    expect(r2.actionData).toMatchObject({ ok: false });
    const r3 = expectPage(
      await page(env, `/writeups/${writeUp.writeup_id}`, {
        cookie,
        form: { csrf: session.csrf, intent: "published", version: "4", confirm_publish: "yes" },
      }),
    );
    expect(r3.actionData).toMatchObject({
      ok: true,
      message: "Moved to published. The change is audited.",
    });
  });
});

describe("radar", () => {
  it("shows the operator radar with its thresholds, never a public view", async () => {
    const { cookie } = await signIn();
    const a = fakeApi((c) => (c.path === "/v0/radar" ? radarFeed : undefined));
    const r = expectPage(await page(envWith(a), "/radar?audience=fleet&days=7", { cookie }));
    expect(a.calls[0].search.get("audience")).toBe("fleet");
    expect(a.calls.some((c) => c.path.startsWith("/v0/public"))).toBe(false);
    const t = text(r.html);
    expect(t).toContain("What counts");
    for (const s of radarFeed.series) expect(t).toContain(s.label);
  });

  it("says the radar is not served yet", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(fakeApi(() => notServed())), "/radar", { cookie }));
    expect(text(r.html)).toContain("Radar: not served yet");
  });
});

describe("actor associations", () => {
  const actorApi = () =>
    fakeApi((c) => {
      if (c.path === "/v0/actor-links") return { items: [actorLinkRecord], truncated: false };
      if (c.path.endsWith("/decision"))
        return { ...actorLinkRecord, status: "confirmed", wording: "confirmed association" };
      return undefined;
    });

  it("shows the API's statement, what matched and the public sources", async () => {
    const { cookie } = await signIn();
    const a = actorApi();
    const r = expectPage(
      await page(envWith(a), `/actors?subject_id=${actorLinkRecord.subject_id}`, { cookie }),
    );
    expect(a.calls[0].search.get("status")).toBe("pending");
    expect(a.calls[0].search.get("subject_id")).toBe(actorLinkRecord.subject_id);
    const t = text(r.html);
    expect(t).toContain(actorLinkRecord.statement);
    expect(t).toContain("Possible association with");
    expect(t).not.toMatch(/attributed to/i);
    expect(t).toContain(actorLinkRecord.sources[0].publisher);
  });

  it("needs a note to confirm, and records decisions", async () => {
    const { cookie, session } = await signIn();
    const a = actorApi();
    const f = { csrf: session.csrf, link_id: actorLinkRecord.link_id };
    const r1 = expectPage(
      await page(envWith(a), "/actors", { cookie, form: { ...f, intent: "confirm", note: "" } }),
    );
    expect(r1.actionData).toMatchObject({ ok: false });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
    const r2 = expectPage(
      await page(envWith(a), "/actors", { cookie, form: { ...f, intent: "reject", note: "" } }),
    );
    expect(a.calls.find((c) => c.method === "POST")?.body).toEqual({
      decision: "reject",
      note: "",
    });
    expect(r2.actionData).toMatchObject({ ok: true });
  });

  it("says actor links are not served yet", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(fakeApi(() => notServed())), "/actors", { cookie }));
    expect(r.html).toContain("issues/29");
  });
});
