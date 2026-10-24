/**
 * The issue's validation path against a mock API: launch an emulator
 * profile, see an attempt appear, confirm the CVE from the review queue, then
 * export. One stateful fake stands in for the control plane.
 */

import { describe, expect, it } from "vitest";
import type { Attempt, Decoy, ReviewItem } from "../lib/api-types";
import type { LiveResponse } from "../lib/live";
import { agents, attempts, catalogue, decoy, reviewItem } from "../test/fixtures";
import {
  envWith,
  expectPage,
  expectRedirect,
  fakeApi,
  page,
  resource,
  signIn,
  text,
} from "../test/harness";

function controlPlane() {
  const state = {
    decoys: [] as Decoy[],
    attempts: [] as Attempt[],
    review: [] as ReviewItem[],
  };
  const api = fakeApi((c) => {
    if (c.path === "/v0/catalogue/entries") return { items: Object.values(catalogue) };
    if (c.path === "/v0/catalogue/entries/emulator/ssl-vpn/portal-generic") return catalogue.ssl;
    if (c.path === "/v0/sensors") return { items: [agents.sensor], next_cursor: null };
    if (c.path === "/v0/audit") return { items: [], next_cursor: null };
    if (c.path === "/v0/decoys" && c.method === "POST") {
      const d = decoy({
        id: "dcy-vpn-1",
        catalogue_id: "emulator/ssl-vpn/portal-generic",
        state: "pending",
      });
      state.decoys.push(d);
      return { decoy: d, job_id: "job-1", job_kind: "decoy.create" };
    }
    if (c.path === "/v0/decoys") return { items: state.decoys, next_cursor: null };
    if (c.path.startsWith("/v0/decoys/")) return state.decoys.find((d) => c.path.endsWith(d.id));
    if (c.path === "/v0/attempts") return { items: state.attempts, truncated: false };
    if (c.path === "/v0/campaigns") return { items: [], truncated: false, notes: [] };
    if (c.path === "/v0/review-queue" && c.method === "GET") {
      const want = c.search.get("status");
      const items = state.review.filter((i) =>
        want === "approved" ? i.status === "approved" : i.status !== "approved",
      );
      return { items, total: items.length, truncated: false, notes: [] };
    }
    if (
      c.path.endsWith("/actions") &&
      c.path.startsWith("/v0/review-queue/") &&
      c.method === "POST"
    ) {
      const item = state.review[0];
      item.status = "approved";
      item.wording = "confirmed";
      item.score = 100;
      item.decided_by = "tok1";
      item.decided_at = Date.now();
      item.note = (c.body as { note: string }).note;
      return { item, effect: "link override recorded as true_positive", writeup_id: null };
    }
    if (c.path === "/v0/exports/stix") {
      return new Response(JSON.stringify({ type: "bundle", id: "bundle--x", objects: [] }), {
        headers: { "content-type": "application/stix+json;version=2.1" },
      });
    }
    return undefined;
  });
  /** The host agent reports the decoy healthy and an attacker arrives. */
  function hostReports() {
    state.decoys[0].state = "healthy";
    const a: Attempt = {
      ...attempts.post,
      decoy_id: "dcy-vpn-1",
      catalogue_id: "emulator/ssl-vpn/portal-generic",
      decoy_kind: "emulation",
      last_seen: Date.now() - 60_000,
    };
    state.attempts.push(a);
    state.review.push({
      ...reviewItem,
      subject: { attempt_id: a.attempt_id, target: "FOILED-DEMO-0001" },
    });
  }
  return { api, state, hostReports };
}

describe("mock happy path", () => {
  it("launch an emulator profile, see the attempt, confirm the CVE, export", async () => {
    const { cookie, session } = await signIn();
    const cp = controlPlane();
    const env = envWith(cp.api);

    // 1. Launch an emulation entry on an edge sensor.
    const confirm =
      "/launch?entry=emulator/ssl-vpn/portal-generic&step=confirm&lifetime=86400&placement=sensor&sensor=sen-0001&key=sssssssssssssssssssssssssssssssssssssssssss";
    expect(text(expectPage(await page(env, confirm, { cookie })).html)).toContain("Confirm launch");
    const launched = await page(env, confirm, {
      cookie,
      form: {
        csrf: session.csrf,
        entry: "emulator/ssl-vpn/portal-generic",
        lifetime: "86400",
        placement: "sensor",
        sensor: "sen-0001",
        idempotency_key: "i".repeat(43),
        risk_ack: "yes",
      },
    });
    expect(expectRedirect(launched)).toBe("/decoys/dcy-vpn-1?launched=1");
    expect(
      text(expectPage(await page(env, "/decoys/dcy-vpn-1?launched=1", { cookie })).html),
    ).toContain("The decoy is pending.");

    // 2. The host reports; the decoy is healthy and an attempt appears.
    cp.hostReports();
    const overview = expectPage(await page(env, "/", { cookie }));
    expect(text(overview.html)).toContain(attempts.post.attempt_id);
    const live = (await (
      await resource(env, `/live?since=${Date.now() - 3600_000}`, "routes/live", { cookie })
    ).json()) as LiveResponse;
    expect(live.ok && live.items.map((i) => i.attempt_id)).toEqual([attempts.post.attempt_id]);

    // 3. Confirm the CVE from the review queue.
    const queue = expectPage(await page(env, "/review", { cookie }));
    expect(text(queue.html)).toContain("We assess as an attempt against FOILED-DEMO-0001");
    const decided = expectPage(
      await page(env, "/review", {
        cookie,
        form: {
          csrf: session.csrf,
          item_id: reviewItem.item_id,
          kind: "cve_link",
          version: "0",
          intent: "approve",
          note: "hook fired, payload matches",
        },
      }),
    );
    expect(decided.actionData).toMatchObject({ ok: true });
    expect(cp.state.review[0].status).toBe("approved");
    const after = expectPage(await page(env, "/review?status=approved", { cookie }));
    expect(text(after.html)).toContain(
      "Confirmed by an analyst as an attempt against FOILED-DEMO-0001",
    );

    // 4. Export.
    const file = await resource(env, "/exports/download", "routes/exports.download", {
      cookie,
      form: { csrf: session.csrf, format: "stix", tlp: "amber", days: "1" },
    });
    expect(file.status).toBe(200);
    expect(file.headers.get("content-disposition")).toMatch(
      /foiled-stix-tlp-amber-\d{8}\.stix\.json/,
    );
    expect(await file.json()).toMatchObject({ type: "bundle" });
  });
});
