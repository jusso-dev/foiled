import { describe, expect, it } from "vitest";
import { actorLink, agents, catalogue, cveLink, llmCveLink } from "../test/fixtures";
import { effectiveTlp, exportFilename } from "./exports";
import { formatDuration, formatOffset, formatTs } from "./format";
import { checkLaunch, configQuery, createBody } from "./launch";
import { campaignSentence, confidenceOf, ledger, levelFor, linkSentence, sortLinks } from "./links";
import {
  type FeedItem,
  feedSignedOut,
  MAX_BACKOFF_MS,
  mergeFeed,
  nextDelay,
  POLL_MS,
} from "./live";
import { safeNext, searchTarget } from "./navigation";
import { SECURITY_HEADERS, withSecurityHeaders } from "./security-headers";

describe("link wording", () => {
  it("says 'we assess as' until an analyst confirms", () => {
    expect(linkSentence(cveLink)).toBe(
      "We assess as an attempt against FOILED-DEMO-0001. Score 100 of 100, not confirmed by an analyst.",
    );
    expect(linkSentence({ ...cveLink, wording: "confirmed" })).toBe(
      "Confirmed by an analyst as an attempt against FOILED-DEMO-0001. Score 100 of 100.",
    );
  });

  it("only ever calls an actor a possible association unless confirmed", () => {
    expect(linkSentence(actorLink)).toMatch(/^Possible association with Example Cluster 7\./);
    expect(linkSentence({ ...actorLink, wording: "confirmed" })).toMatch(/^Possible association/);
    expect(linkSentence({ ...actorLink, wording: "confirmed association" })).toMatch(
      /^Confirmed association with/,
    );
  });

  it("words campaigns as possible", () => {
    expect(campaignSentence(55, "possible")).toMatch(/^Possible campaign/);
    expect(campaignSentence(100, "confirmed")).toMatch(/^Confirmed by an analyst/);
  });

  it("escapes hostile targets", () => {
    expect(linkSentence({ ...actorLink, target: "A‮b" })).toContain("A\\u{202e}b");
  });

  it("maps chips: confirmed only after an analyst, unconfirmed high is probable", () => {
    expect(levelFor("we assess as", "high")).toBe("probable");
    expect(levelFor("we assess as", "medium")).toBe("assessed");
    expect(levelFor("possible association", "high")).toBe("probable");
    expect(levelFor("confirmed", "low")).toBe("confirmed");
    expect(confidenceOf({ score: 140, band: "high", wording: "confirmed" })).toEqual({
      level: "confirmed",
      score: 100,
    });
  });

  it("builds the ledger from recorded contributions", () => {
    expect(ledger(cveLink)).toEqual([
      {
        id: "sequence-0",
        signal: "probe, upload, write in order",
        source: "Request sequence",
        points: 36,
      },
      {
        id: "vuln_path_hook-1",
        signal: "vulnerable path ran",
        source: "Vulnerable-path hook",
        points: 60,
      },
      {
        id: "catalogue_prior-2",
        signal: "decoy stood up for this CVE",
        source: "Catalogue prior",
        points: 10,
      },
    ]);
  });

  it("orders CVEs first, strongest first", () => {
    expect(sortLinks([actorLink, llmCveLink, cveLink]).map((l) => [l.kind, l.score])).toEqual([
      ["attempt_cve", 100],
      ["attempt_cve", 20],
      ["attempt_actor", 45],
    ]);
  });
});

describe("launch rules", () => {
  const params = (q: string) => new URLSearchParams(q);
  const sensors = [agents.sensor, agents.revoked];

  it("accepts an emulation entry on an emulation-only sensor", () => {
    const c = checkLaunch(
      params("placement=sensor&sensor=sen-0001&lifetime=3600"),
      catalogue.ssl,
      sensors,
      false,
    );
    expect(c.errors).toEqual({});
    expect(createBody(c.config)).toEqual({
      catalogue_id: "emulator/ssl-vpn/portal-generic",
      lifetime_seconds: 3600,
      sensor_id: "sen-0001",
    });
    expect(configQuery(c.config)).toBe(
      "entry=emulator%2Fssl-vpn%2Fportal-generic&lifetime=3600&placement=sensor&sensor=sen-0001",
    );
  });

  it("refuses a sandbox entry on a sensor that does not allow sandboxes, and revoked sensors", () => {
    expect(
      checkLaunch(params("placement=sensor&sensor=sen-0001"), catalogue.demo, sensors, true).errors
        .sensor,
    ).toBe("That sensor does not allow sandboxes.");
    expect(
      checkLaunch(params("placement=sensor&sensor=sen-0002"), catalogue.ssl, sensors, true).errors
        .sensor,
    ).toBe("That sensor is revoked.");
  });

  it("defaults to 24 hours in the research host pool and refuses odd lifetimes", () => {
    const c = checkLaunch(params(""), catalogue.demo, sensors, false);
    expect(c.config).toMatchObject({ lifetime: 86400, placement: "pool" });
    expect(createBody(c.config)).toEqual({
      catalogue_id: "foiled/demo-app/1.0.0",
      lifetime_seconds: 86400,
    });
    expect(
      checkLaunch(params("lifetime=999999"), catalogue.demo, sensors, false).errors.lifetime,
    ).toBeDefined();
  });

  it("needs an explicit opt-in and decoys:elevate for drafts", () => {
    expect(checkLaunch(params(""), catalogue.redis, sensors, true).errors.allow_draft).toMatch(
      /opt-in/,
    );
    expect(
      checkLaunch(params("allow_draft=yes"), catalogue.redis, sensors, false).errors.allow_draft,
    ).toMatch(/decoys:elevate/);
    const ok = checkLaunch(params("allow_draft=yes"), catalogue.redis, sensors, true);
    expect(ok.errors).toEqual({});
    expect(createBody(ok.config).allow_draft).toBe(true);
  });

  it("never launches a deprecated entry", () => {
    const dep = { ...catalogue.ssl, status: "deprecated" as const };
    expect(checkLaunch(params(""), dep, sensors, true).errors.entry).toBeDefined();
  });
});

describe("navigation helpers", () => {
  it("keeps post-sign-in redirects on this site", () => {
    expect(safeNext("/attempts?x=1")).toBe("/attempts?x=1");
    for (const bad of [
      "//evil.example",
      "https://evil.example",
      "/\\evil",
      "/a\r\nSet-Cookie: x",
      "/login",
      null,
    ]) {
      expect(safeNext(bad)).toBe("/");
    }
  });

  it("routes jump box queries", () => {
    expect(searchTarget("ioc_0123456789abcdef01234567")).toBe("/iocs/ioc_0123456789abcdef01234567");
    expect(searchTarget("cmp_0123456789abcdef01234567")).toBe(
      "/campaigns/cmp_0123456789abcdef01234567",
    );
    expect(searchTarget("foiled-demo-0001")).toBe("/attempts?cve=FOILED-DEMO-0001");
    expect(searchTarget("2001:db8::1")).toBe("/attempts?src=2001%3Adb8%3A%3A1");
    expect(searchTarget("  ")).toBe("/");
  });
});

describe("live feed", () => {
  const item = (id: string, last: number, state: FeedItem["state"] = "probe"): FeedItem => ({
    attempt_id: id,
    src: "198.51.100.1",
    catalogue_id: "x/y",
    decoy_kind: "emulation",
    state,
    last_seen: last,
    hook_hits: 0,
  });

  it("merges a backfill: updates seen attempts, adds new ones, keeps the newest", () => {
    const merged = mergeFeed([item("a", 1), item("b", 2)], [item("a", 5, "exploit"), item("c", 3)]);
    expect(merged.map((i) => [i.attempt_id, i.state])).toEqual([
      ["a", "exploit"],
      ["c", "probe"],
      ["b", "probe"],
    ]);
    const many = Array.from({ length: 30 }, (_, i) => item(`x${i}`, i));
    expect(mergeFeed([], many)).toHaveLength(20);
    expect(mergeFeed([], many)[0].attempt_id).toBe("x29");
  });

  it("does not let a stale backfill overwrite newer state", () => {
    expect(mergeFeed([item("a", 9, "exploit")], [item("a", 4)])[0].state).toBe("exploit");
  });

  it("recognises a signed-out answer so the feed stops instead of backing off", () => {
    expect(feedSignedOut(401, false, { ok: false, error: "x", signedOut: true })).toBe(true);
    expect(feedSignedOut(200, true, null)).toBe(true);
    expect(feedSignedOut(502, false, { ok: false, error: "API down" })).toBe(false);
    expect(feedSignedOut(200, false, { ok: true, items: [], cursor: 1, gap: false, at: 1 })).toBe(
      false,
    );
  });

  it("backs off after failures with bounded jitter", () => {
    expect(nextDelay(0)).toBe(POLL_MS);
    expect(nextDelay(1, () => 0)).toBe(30_000);
    expect(nextDelay(2, () => 0)).toBe(60_000);
    expect(nextDelay(3, () => 0)).toBe(MAX_BACKOFF_MS);
    expect(nextDelay(50, () => 1)).toBe(MAX_BACKOFF_MS * 1.2);
  });
});

describe("exports", () => {
  it("raises unreviewed exports to AMBER+STRICT unless already RED", () => {
    expect(effectiveTlp("clear", true)).toBe("amber+strict");
    expect(effectiveTlp("red", true)).toBe("red");
    expect(effectiveTlp("green", false)).toBe("green");
  });

  it("names files with the format, TLP, date and markers", () => {
    const now = Date.UTC(2026, 9, 18);
    expect(exportFilename("misp", "amber+strict", { unreviewed: true, partial: false, now })).toBe(
      "foiled-misp-tlp-amber-strict-20261018-unreviewed.misp.json",
    );
  });
});

describe("formats", () => {
  it("follows the voice guide", () => {
    expect(formatTs(Date.UTC(2026, 9, 18, 4, 2))).toBe("2026-10-18 04:02");
    expect(formatTs(Number.NaN)).toBe("");
    expect(formatOffset(412)).toBe("+0.412s");
    expect(formatOffset(83_000)).toBe("+1m 23s");
    expect(formatDuration(3_780_000)).toBe("1h 03m");
  });
});

describe("security headers", () => {
  it("adds framing, sniffing, referrer and cache headers without overriding route headers", () => {
    const res = withSecurityHeaders(new Response("x", { headers: { "cache-control": "public" } }));
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k)).toBe(v);
    expect(res.headers.get("cache-control")).toBe("public");
    expect(withSecurityHeaders(new Response("x")).headers.get("cache-control")).toBe("no-store");
    const redirect = withSecurityHeaders(Response.redirect("https://console.test/login", 302));
    expect(redirect.headers.get("x-frame-options")).toBe("DENY");
  });
});
