import { describe, expect, it } from "vitest";
import type { Attempt } from "../lib/api-types";
import { actorLink, attempts, cveLink, HOSTILE, ioc, llmCveLink, timeline } from "../test/fixtures";
import {
  ADMIN,
  type ApiCall,
  envWith,
  expectPage,
  expectRedirect,
  fakeApi,
  page,
  signIn,
  text,
} from "../test/harness";

const ID = attempts.post.attempt_id;

function api(over: Partial<Attempt> = {}, extra?: (c: ApiCall) => unknown) {
  return fakeApi((c) => {
    const hit = extra?.(c);
    if (hit !== undefined) return hit;
    if (c.path === "/v0/attempts")
      return { items: [attempts.post, attempts.probe], truncated: false };
    if (c.path === `/v0/attempts/${ID}`) return { ...attempts.post, ...over };
    if (c.path === `/v0/attempts/${ID}/timeline`) return timeline;
    if (c.path === `/v0/attempts/${ID}/links`) {
      return c.method === "POST"
        ? { ...cveLink, score: 100, wording: "confirmed" }
        : { items: [llmCveLink, actorLink, cveLink] };
    }
    if (c.path === `/v0/attempts/${ID}/iocs`) {
      return { attempt_id: ID, file_ioc_limited: false, notes: [], items: [ioc], truncated: false };
    }
    if (c.path === "/v0/iocs") return { items: [ioc], truncated: false };
    if (c.path.startsWith("/v0/iocs/")) return ioc;
    return undefined;
  });
}

describe("attempt triage", () => {
  it("passes filters to the API and lists attempts", async () => {
    const { cookie } = await signIn();
    const a = api();
    const r = expectPage(
      await page(
        envWith(a),
        "/attempts?window=24h&state=exploit&technique=t1190&min_confidence=60&src=203.0.113.7",
        { cookie },
      ),
    );
    const q = a.calls[0].search;
    expect(q.get("state")).toBe("exploit");
    expect(q.get("technique")).toBe("T1190");
    expect(q.get("min_confidence")).toBe("60");
    expect(q.get("src")).toBe("203.0.113.7");
    expect(Number(q.get("since"))).toBeGreaterThan(Date.now() - 25 * 3600_000);
    expect(r.html).toContain(`/attempts/${ID}?since=`);
  });

  it("drops filter values the API would refuse", async () => {
    const { cookie } = await signIn();
    const a = api();
    await page(envWith(a), "/attempts?technique=../x&state=owned&decoy_id=../../audit", { cookie });
    const q = a.calls[0].search;
    expect(q.has("technique")).toBe(false);
    expect(q.has("state")).toBe(false);
    expect(q.has("decoy_id")).toBe(false);
  });

  it("shows the timeline, links with explainability and indicators", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(api()), `/attempts/${ID}`, { cookie }));
    const t = text(r.html);
    // Timeline with offsets and state changes.
    expect(t).toContain("+0.000s");
    expect(t).toContain("state post-exploitation on hook post exploit");
    // CVE link: "we assess as" wording, every contribution, evidence and flags.
    expect(t).toContain(
      "We assess as an attempt against FOILED-DEMO-0001. Score 100 of 100, not confirmed by an analyst.",
    );
    expect(t).toContain("Vulnerable-path hook");
    expect(t).toContain("+60");
    expect(t).toContain("probe, upload, write in order");
    expect(t).toContain("Publishable in exports");
    // LLM-only link: the cap is shown in words.
    expect(t).toContain("LLM-only evidence capped below high");
    // Actor: possible association, never fact.
    expect(t).toContain("Possible association with Example Cluster 7.");
    expect(t).not.toMatch(/Confirmed association/);
    // Noise and indicators.
    expect(t).toContain("203[.]0[.]113[.]7");
    // CVE ids appear only with their chips.
    expect(r.html).toContain('data-confidence="probable"');
  });

  it("records an analyst override with a note", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), `/attempts/${ID}`, {
        cookie,
        form: {
          csrf: session.csrf,
          intent: "override",
          kind: "attempt_cve",
          target: "FOILED-DEMO-0001",
          feedback: "true_positive",
          note: "hook and payload match",
        },
      }),
    );
    const post = a.calls.find((c) => c.method === "POST");
    expect(post?.path).toBe(`/v0/attempts/${ID}/links`);
    expect(post?.body).toEqual({
      kind: "attempt_cve",
      target: "FOILED-DEMO-0001",
      feedback: "true_positive",
      note: "hook and payload match",
    });
    expect(text(r.html)).toContain('Recorded. The link now scores 100 and is worded "confirmed".');
  });

  it("does not accept IOC link overrides or empty notes", async () => {
    const { cookie, session } = await signIn();
    const a = api();
    const base = { csrf: session.csrf, intent: "override", target: "x", feedback: "unsure" };
    const r1 = expectPage(
      await page(envWith(a), `/attempts/${ID}`, {
        cookie,
        form: { ...base, kind: "attempt_ioc", note: "n" },
      }),
    );
    expect(r1.actionData).toMatchObject({ ok: false });
    const r2 = expectPage(
      await page(envWith(a), `/attempts/${ID}`, {
        cookie,
        form: { ...base, kind: "attempt_cve", note: "" },
      }),
    );
    expect(r2.actionData).toMatchObject({ ok: false, message: "Add a note that says why." });
    expect(a.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("hides the override form from tokens without attempts:write", async () => {
    const { cookie } = await signIn({ ...ADMIN, scopes: ["attempts:read", "iocs:read"] });
    const r = expectPage(await page(envWith(api()), `/attempts/${ID}`, { cookie }));
    expect(text(r.html)).not.toContain("Record override");
  });

  it("renders attacker text as inert, visible text", async () => {
    const { cookie } = await signIn();
    const hostileTimeline = {
      ...timeline,
      entries: [{ ...timeline.entries[0], summary: HOSTILE }],
    };
    const a = api({ src: HOSTILE, labels: { note: HOSTILE } }, (c) =>
      c.path.endsWith("/timeline") ? hostileTimeline : undefined,
    );
    const r = expectPage(await page(envWith(a), `/attempts/${ID}`, { cookie }));
    expect(r.html).not.toContain("<img");
    expect(r.html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(r.html).not.toContain("‮");
    expect(r.html).toContain("\\u{202e}gnp.exe\\x07");
  });

  it("lets a panel fail without taking the page down", async () => {
    const { cookie } = await signIn();
    const a = api({}, (c) =>
      c.path.endsWith("/timeline") ? new Response("boom", { status: 500 }) : undefined,
    );
    const r = expectPage(await page(envWith(a), `/attempts/${ID}`, { cookie }));
    expect(r.status).toBe(200);
    expect(text(r.html)).toContain("Could not load timeline");
    expect(text(r.html)).toContain("We assess as an attempt against FOILED-DEMO-0001");
  });
});

describe("IOC browser", () => {
  it("searches by value and renders the defanged display, never the raw value", async () => {
    const { cookie } = await signIn();
    const a = api();
    const r = expectPage(
      await page(envWith(a), "/iocs?value=203[.]0[.]113[.]7&type=ip", { cookie }),
    );
    expect(a.calls[0].search.get("value")).toBe("203[.]0[.]113[.]7");
    expect(a.calls[0].search.get("type")).toBe("ip");
    expect(r.html).toContain("203[.]0[.]113[.]7");
    expect(r.html).not.toContain(">203.0.113.7<");
  });

  it("shows an indicator with its confidence and where it was seen", async () => {
    const { cookie } = await signIn();
    const r = expectPage(await page(envWith(api()), `/iocs/${ioc.ioc_id}`, { cookie }));
    const t = text(r.html);
    expect(t).toContain("We assess as an indicator from these attempts.");
    expect(t).toContain(ioc.attempt_ids[0]);
  });
});

describe("jump box", () => {
  it("routes ids, CVEs, techniques and addresses to the right page", async () => {
    const { cookie } = await signIn();
    const env = envWith(api());
    const go = async (q: string) =>
      expectRedirect(await page(env, `/search?q=${encodeURIComponent(q)}`, { cookie }));
    expect(await go(ID)).toBe(`/attempts/${ID}`);
    expect(await go("cve-2099-0001")).toBe("/attempts?cve=CVE-2099-0001");
    expect(await go("t1190")).toBe("/attempts?technique=T1190");
    expect(await go("198.51.100.23")).toBe("/attempts?src=198.51.100.23");
    expect(await go("hxxp://example.invalid/x")).toBe(
      "/iocs?value=hxxp%3A%2F%2Fexample.invalid%2Fx",
    );
  });
});
