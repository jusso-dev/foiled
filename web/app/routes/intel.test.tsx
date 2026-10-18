import { describe, expect, it } from "vitest";
import type { Campaign, ConfidenceLink } from "../lib/api-types";
import { campaign, quarantined } from "../test/fixtures";
import {
  ADMIN,
  apiError,
  envWith,
  expectPage,
  fakeApi,
  json,
  notServed,
  page,
  resource,
  signIn,
  text,
} from "../test/harness";

const CID = campaign.campaign_id;

function campaignApi(c2: Campaign = campaign) {
  const link: ConfidenceLink = {
    kind: "attempt_campaign",
    attempt_id: c2.seed.attempt_id,
    target: CID,
    score: c2.confidence.score,
    band: c2.confidence.band,
    wording: c2.confidence.wording,
    evidence: c2.confidence.evidence,
    contributions: [
      {
        source: "campaign_cluster",
        points: c2.confidence.score,
        signal_ids: c2.confidence.evidence.map((e) => e.signal_id),
      },
    ],
    caps_applied: c2.confidence.caps_applied,
    publishable: false,
    ui_highlight: false,
    auto_state_promote: false,
    radar_queue: false,
  };
  return fakeApi((c) => {
    if (c.path === "/v0/campaigns") return { items: [c2], truncated: false, notes: [] };
    if (c.path === `/v0/campaigns/${CID}`) return c2;
    if (c.path === `/v0/campaigns/${CID}/evidence`) {
      return {
        campaign_id: CID,
        confidence: link,
        members: [{ ...link, attempt_id: c2.members[1].attempt_id }],
        bridges: [
          {
            campaign_id: CID,
            merged_campaign_id: null,
            attempt_id: c2.members[0].attempt_id,
            with_attempt_id: c2.members[1].attempt_id,
            signal_id: "campaign:payload_sha256:5e884898da28",
            feature: "payload_sha256",
            attempt_side: 1,
            with_side: 1,
            small_halves: true,
            recorded_at: c2.first_seen,
          },
        ],
        possible_links: [],
        truncated: false,
      };
    }
    if (c.path === `/v0/campaigns/${CID}/actions`) {
      if (c.method === "POST") {
        return {
          action: {
            action_id: "act-1",
            kind: "label",
            campaign_id: CID,
            anchor_attempt_ids: [],
            note: "n",
            analyst_id: "tok1",
            at: 1,
          },
          campaign: c2,
        };
      }
      return { campaign_id: CID, items: [] };
    }
    return undefined;
  });
}

describe("campaigns", () => {
  it("lists campaigns with 'possible' wording until confirmed", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(campaignApi()), "/campaigns", { cookie }));
    expect(r.html).toContain("Possible campaign: these attempts may share an operator.");
    expect(text(r.html)).toContain("Payload hash");
  });

  it("shows members, joins, bridges and actor associations as possible only", async () => {
    const { cookie } = await signIn();
    const withActor: Campaign = {
      ...campaign,
      suggested_actor_links: [
        {
          link_id: "acl_000000000000000000000001",
          actor_id: "report:example-cluster-07",
          label: "Example Cluster 7",
          wording: "possible association",
          score: 35,
          band: "low",
          status: "pending",
          confidence_ref: "/v0/actor-links/acl_000000000000000000000001",
          report_urls: ["https://example.invalid/report", "javascript:alert(1)"],
        },
      ],
    };
    const r = expectPage(
      await page(envWith(campaignApi(withActor)), `/campaigns/${CID}`, { cookie }),
    );
    const t = text(r.html);
    for (const m of campaign.members) expect(t).toContain(m.attempt_id);
    expect(t).toContain("payload sha256");
    expect(t).toContain("small halves: audit");
    expect(t).toContain("Possible association with Example Cluster 7");
    expect(r.html).toContain('href="https://example.invalid/report"');
    expect(r.html).not.toContain('href="javascript:');
    expect(t).toContain(`Member ${campaign.members[1].attempt_id}`);
  });

  it("splits ticked members with a note", async () => {
    const { cookie, session } = await signIn();
    const a = campaignApi();
    const member = campaign.members[0].attempt_id;
    expectPage(
      await page(envWith(a), `/campaigns/${CID}?since=1&until=2`, {
        cookie,
        form: {
          csrf: session.csrf,
          intent: "split",
          attempt_ids: [member],
          note: "different payload",
        },
      }),
    );
    const post = a.calls.find((c) => c.method === "POST");
    expect(post?.body).toEqual({
      action: "split",
      attempt_ids: [member],
      note: "different payload",
    });
    expect(post?.search.get("since")).toBe("1");
  });

  it("refuses a merge into itself and malformed ids", async () => {
    const { cookie, session } = await signIn();
    const a = campaignApi();
    const r = expectPage(
      await page(envWith(a), `/campaigns/${CID}`, {
        cookie,
        form: { csrf: session.csrf, intent: "merge", campaign_ids: `${CID} ../x`, note: "n" },
      }),
    );
    expect(r.actionData).toMatchObject({ ok: false });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("explains a campaign outside the window", async () => {
    const { cookie } = await signIn();
    const a = fakeApi((c) =>
      c.path === `/v0/campaigns/${CID}`
        ? {
            campaign_id: CID,
            tenant_id: "t1",
            stub: true,
            first_seen: 1000,
            last_seen: 5000,
            attempt_count: 4,
            merged_into: null,
            notes: [],
          }
        : { campaign_id: CID, items: [] },
    );
    const r = expectPage(await page(envWith(a), `/campaigns/${CID}`, { cookie }));
    expect(text(r.html)).toContain(
      "Fewer than two of this campaign's 4 attempts are in the current window.",
    );
  });
});

describe("exports", () => {
  function exportApi(headers: Record<string, string> = {}) {
    return fakeApi((c) =>
      c.path.startsWith("/v0/exports/")
        ? new Response("indicator_type,indicator\nip,203.0.113.7\n", {
            headers: { "content-type": "text/csv", ...headers },
          })
        : undefined,
    );
  }

  it("downloads through the Worker with TLP and review markers in the name", async () => {
    const { cookie, session } = await signIn();
    const a = exportApi({ "x-foiled-truncated": "true" });
    const res = await resource(envWith(a), "/exports/download", "routes/exports.download", {
      cookie,
      form: {
        csrf: session.csrf,
        format: "ioc-csv",
        tlp: "green",
        days: "7",
        include_unreviewed: "yes",
        include_actors: "yes",
      },
    });
    expect(res.status).toBe(200);
    const q = a.calls[0].search;
    expect(a.calls[0].path).toBe("/v0/exports/iocs.csv");
    expect(q.get("fields")).toBe("ioc");
    expect(q.get("tlp")).toBe("green");
    expect(q.get("include_unreviewed")).toBe("true");
    expect(q.get("include_actors")).toBe("true");
    expect(a.calls[0].headers.get("authorization")).toMatch(/^Bearer /);
    const cd = res.headers.get("content-disposition") ?? "";
    expect(cd).toMatch(
      /^attachment; filename="foiled-ioc-csv-tlp-amber-strict-\d{8}-unreviewed-partial\.csv"$/,
    );
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.text()).toContain("203.0.113.7");
  });

  it("sends the shipped source CSV with only its window", async () => {
    const { cookie, session } = await signIn();
    const a = exportApi();
    await resource(envWith(a), "/exports/download", "routes/exports.download", {
      cookie,
      form: { csrf: session.csrf, format: "source-csv", tlp: "red", include_unreviewed: "yes" },
    });
    const q = a.calls[0].search;
    expect([...q.keys()]).toEqual(["since"]);
  });

  it("returns to the form with a reason when a format is not served", async () => {
    const { cookie, session } = await signIn();
    const res = await resource(
      envWith(fakeApi(() => notServed())),
      "/exports/download",
      "routes/exports.download",
      {
        cookie,
        form: { csrf: session.csrf, format: "stix" },
      },
    );
    expect(res.headers.get("location")).toBe("/exports?failed=404&format=stix&not_served=1");
    const r = expectPage(
      await page(
        envWith(fakeApi(() => undefined)),
        "/exports?failed=404&format=stix&not_served=1",
        { cookie },
      ),
    );
    expect(text(r.html)).toContain(
      "STIX 2.1 bundle: That export format is not served by this API yet.",
    );
  });

  it("refuses a download without the CSRF token", async () => {
    const { cookie } = await signIn();
    const a = exportApi();
    const res = await resource(envWith(a), "/exports/download", "routes/exports.download", {
      cookie,
      form: { csrf: "x", format: "source-csv" },
    });
    expect(res.status).toBe(403);
    expect(a.calls).toHaveLength(0);
  });

  it("disables unreviewed exports without review:write", async () => {
    const { cookie } = await signIn({ ...ADMIN, scopes: ["exports:read"] });
    const r = expectPage(await page(envWith(fakeApi(() => undefined)), "/exports", { cookie }));
    const input = r.html.match(/<input[^>]*name="include_unreviewed"[^>]*>/)?.[0] ?? "";
    expect(input).toContain('disabled=""');
  });
});

describe("quarantine downloads", () => {
  const qApi = () =>
    fakeApi((c) => {
      if (c.path === "/v0/quarantine") return { items: [quarantined], next_cursor: null };
      if (c.method === "POST")
        return { url: "https://r2.example.invalid/one-time", expires_at: Date.now() + 60_000 };
      return undefined;
    });

  it("is off by default", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(qApi()), "/quarantine", { cookie }));
    expect(text(r.html)).toContain("Downloads are off");
    expect(r.html).not.toContain("?confirm=");
    const { session } = await signIn();
    const post = expectPage(
      await page(envWith(qApi()), "/quarantine", {
        cookie,
        form: {
          csrf: session.csrf,
          sha256: quarantined.sha256,
          confirm_sha256: quarantined.sha256,
          ack_live: "yes",
          note: "n",
        },
      }),
    );
    expect(post.status).toBe(403);
  });

  it("needs both confirmations when turned on", async () => {
    const { cookie, session } = await signIn();
    const a = qApi();
    const env = envWith(a, { QUARANTINE_DOWNLOADS: "on" });
    const list = expectPage(await page(env, "/quarantine", { cookie }));
    expect(list.html).toContain(`/quarantine?confirm=${quarantined.sha256}`);
    const step1 = expectPage(
      await page(env, `/quarantine?confirm=${quarantined.sha256}`, { cookie }),
    );
    expect(text(step1.html)).toContain("Type the full SHA-256 to confirm");
    const base = {
      csrf: session.csrf,
      sha256: quarantined.sha256,
      ack_live: "yes",
      note: "reverse engineering",
    };
    const wrong = expectPage(
      await page(env, `/quarantine?confirm=${quarantined.sha256}`, {
        cookie,
        form: { ...base, confirm_sha256: "0".repeat(64) },
      }),
    );
    expect(wrong.actionData).toMatchObject({
      ok: false,
      message: "The typed SHA-256 does not match the file.",
    });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
    const ok = expectPage(
      await page(env, `/quarantine?confirm=${quarantined.sha256}`, {
        cookie,
        form: { ...base, confirm_sha256: quarantined.sha256 },
      }),
    );
    expect(a.calls.find((c) => c.method === "POST")?.path).toBe(
      `/v0/quarantine/${quarantined.sha256}:download`,
    );
    expect(ok.html).toContain('href="https://r2.example.invalid/one-time"');
  });

  it("reports the planned list endpoint as not served", async () => {
    const { cookie } = await signIn();
    const r = expectPage(
      await page(
        envWith(
          fakeApi(() => json({ error: { code: "not_found", message: "route not found" } }, 404)),
        ),
        "/quarantine",
        { cookie },
      ),
    );
    expect(text(r.html)).toContain("Quarantine: not served yet");
  });
});

describe("rate limits and scopes", () => {
  it("shows the API's rate limit in words", async () => {
    const { cookie, session } = await signIn();
    const limited = fakeApi((c) => {
      if (c.method === "POST") return apiError(429, "rate_limited", "too many requests");
      if (c.path === `/v0/campaigns/${CID}`) return campaign;
      if (c.path.endsWith("/actions")) return { campaign_id: CID, items: [] };
      return undefined;
    });
    const r = expectPage(
      await page(envWith(limited), `/campaigns/${CID}`, {
        cookie,
        form: { csrf: session.csrf, intent: "label", title: "x", note: "n" },
      }),
    );
    expect(r.actionData).toMatchObject({
      ok: false,
      message: "Rate limited. Wait and try again. too many requests",
    });
  });
});
