import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AppShell, NAV_ITEMS } from "./AppShell";
import { AttackMap, landPath, project } from "./AttackMap";
import { ConfidenceChip } from "./ConfidenceChip";
import { CveRef } from "./CveRef";
import { ExploitTable } from "./ExploitTable";
import { IocTable } from "./IocTable";
import { LAND_COLS, LAND_RLE, LAND_ROWS } from "./map/world-land";
import { RawRequestBlock } from "./RawRequestBlock";
import { Sparkline, sparklinePath } from "./Sparkline";

const html = (el: React.ReactElement) => renderToStaticMarkup(el);

describe("ConfidenceChip", () => {
  it("uses 'we assess as' wording for assessed", () => {
    const out = html(<ConfidenceChip level="assessed" score={64} subject="CVE-2099-EXAMPLE1" />);
    expect(out).toContain("chip--assessed");
    expect(out).toContain("Assessed 64");
    expect(out).toContain("We assess as an attempt against CVE-2099-EXAMPLE1");
    expect(out).toContain("not confirmed by an analyst");
    expect(out).not.toContain("Confirmed by");
  });

  it("uses probable wording without claiming confirmation", () => {
    const out = html(<ConfidenceChip level="probable" score={81} />);
    expect(out).toContain("chip--probable");
    expect(out).toContain("Probable 81");
    expect(out).toContain("not yet confirmed by an analyst");
    expect(out).not.toContain("We assess as");
  });

  it("says confirmed only for the confirmed level", () => {
    const out = html(<ConfidenceChip level="confirmed" score={96} subject="CVE-2099-EXAMPLE2" />);
    expect(out).toContain("chip--confirmed");
    expect(out).toContain("Confirmed 96");
    expect(out).toContain("Confirmed by an analyst as an attempt against CVE-2099-EXAMPLE2");
  });

  it("clamps the score to 0 to 100", () => {
    expect(html(<ConfidenceChip level="assessed" score={140} />)).toContain("Assessed 100");
    expect(html(<ConfidenceChip level="assessed" score={-3} />)).toContain("Assessed 0");
  });
});

describe("CveRef", () => {
  it("renders the id with a confidence chip", () => {
    const out = html(
      <CveRef id="CVE-2099-EXAMPLE1" confidence={{ level: "assessed", score: 64 }} />,
    );
    expect(out).toContain("CVE-2099-EXAMPLE1");
    expect(out).toContain("chip--assessed");
  });

  it("requires a confidence prop and says so when a row lacks one", () => {
    // @ts-expect-error confidence is a required prop: this line must not type-check.
    expect(html(<CveRef id="CVE-2099-EXAMPLE1" />)).toContain("confidence missing");
    const bad = { level: "assessed" } as unknown as { level: "assessed"; score: number };
    const out = html(<CveRef id="CVE-2099-EXAMPLE1" confidence={bad} />);
    expect(out).toContain("confidence missing");
    expect(out).not.toContain("chip--");
  });

  it("every CVE in the exploit table has a chip in its row", () => {
    const out = html(
      <ExploitTable
        caption="example"
        rows={[
          {
            key: "1",
            ago: "1m",
            cve: "CVE-2099-EXAMPLE1",
            technology: "ExampleVPN",
            confidence: { level: "probable", score: 81 },
          },
        ]}
      />,
    );
    const rows = out.split("<tr>").filter((r) => r.includes("CVE-2099-EXAMPLE1"));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain("chip--probable");
  });
});

describe("RawRequestBlock", () => {
  it("escapes attacker markup instead of rendering it", () => {
    const out = html(<RawRequestBlock raw="<script>alert(1)</script>" />);
    expect(out).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(out).not.toContain("<script>");
  });

  it("shows control and bidi characters as visible escapes", () => {
    const out = html(<RawRequestBlock raw={"a\u001b[31mb‮c"} />);
    expect(out).toContain("\\x1b[31m");
    expect(out).toContain("\\u{202e}");
    expect(out).not.toContain("‮");
  });

  it("truncates long payloads and says so", () => {
    const out = html(<RawRequestBlock raw={"A".repeat(5000)} maxChars={100} />);
    expect(out).toContain("A".repeat(100));
    expect(out).not.toContain("A".repeat(101));
    expect(out).toContain("Truncated: showing 100 of 5,000 characters");
  });

  it("does not show a truncation note for short text", () => {
    expect(html(<RawRequestBlock raw="GET / HTTP/1.1" />)).not.toContain("Truncated");
  });
});

describe("IocTable", () => {
  it("renders attacker-derived values as text", () => {
    const out = html(
      <IocTable
        caption="example"
        rows={[
          {
            key: "1",
            type: "user-agent",
            value: "<img src=x onerror=alert(1)>",
            firstSeen: "a",
            lastSeen: "b",
            count: 1,
          },
        ]}
      />,
    );
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img");
  });
});

describe("sparklinePath", () => {
  it("maps min to the bottom and max to the top inside the padding", () => {
    expect(sparklinePath([0, 10], 100, 20, 2)).toBe("M0 18L100 2");
  });

  it("spaces points evenly across the width", () => {
    expect(sparklinePath([1, 2, 3, 2, 1], 40, 10, 0)).toBe("M0 10L10 5L20 0L30 5L40 10");
  });

  it("draws a centred line for a flat series or a single value", () => {
    expect(sparklinePath([5, 5, 5], 60, 20)).toBe("M0 10L30 10L60 10");
    expect(sparklinePath([7], 60, 20)).toBe("M0 10L60 10");
  });

  it("returns an empty path for no finite values", () => {
    expect(sparklinePath([], 60, 20)).toBe("");
    expect(sparklinePath([Number.NaN], 60, 20)).toBe("");
  });

  it("renders an SVG path and is decorative without a label", () => {
    const out = html(<Sparkline values={[0, 10]} width={100} height={20} />);
    expect(out).toContain('d="M0 18L100 2"');
    expect(out).toContain('aria-hidden="true"');
    expect(html(<Sparkline values={[1, 2]} label="Rising" />)).toContain('aria-label="Rising"');
  });
});

describe("AttackMap", () => {
  const hotspots = [
    { id: "src-a", label: "Example A", lon: -77, lat: 38.9, weight: 1 },
    { id: "src-b", label: "Example B", lon: 116.4, lat: 39.9, weight: 0.5 },
  ];
  const sensors = [
    { id: "syd", label: "SYD-EDGE-03", lon: 151.2, lat: -33.9, hits: 88, callout: true },
  ];

  it("projects longitude and latitude into the 1000 x 500 canvas", () => {
    expect(project({ lon: -180, lat: 90 })).toEqual([0, 0]);
    expect(project({ lon: 0, lat: 0 })).toEqual([500, 250]);
    expect(project({ lon: 180, lat: -90 })).toEqual([1000, 500]);
  });

  it("renders one glowing hotspot per point at the projected position", () => {
    const out = html(
      <AttackMap hotspots={hotspots} sensors={sensors} arcs={[{ from: "src-a", to: "syd" }]} />,
    );
    expect(out.match(/data-hotspot="/g)).toHaveLength(2);
    expect(out).toContain('data-hotspot="src-a"');
    expect(out).toContain('data-hotspot="src-b"');
    const [x, y] = project(hotspots[0]);
    expect(out).toContain(`cx="${Math.round(x * 10) / 10}" cy="${Math.round(y * 10) / 10}"`);
    expect(out).toMatch(/filter="url\(#[^)]+-glow\)"/);
    // Glow on hotspots only, never on sensors (#39).
    expect(out.match(/filter="url\(/g)).toHaveLength(2);
    // Nothing is cropped: the whole map fits whatever the panel width.
    expect(out).toContain('preserveAspectRatio="xMidYMid meet"');
    expect(out).toContain("SYD-EDGE-03 · 88");
    expect(out.match(/<path d="M[^"]*Q/g)).toHaveLength(1);
  });

  it("skips arcs whose ends are unknown", () => {
    const out = html(<AttackMap hotspots={hotspots} arcs={[{ from: "src-a", to: "nowhere" }]} />);
    expect(out.match(/<path d="M[^"]*Q/g)).toBeNull();
  });

  it("offers Map, Globe, Heatmap and AU with only Map built", () => {
    const out = html(<AttackMap hotspots={[]} />);
    for (const v of ["Map", "Globe", "Heatmap", "AU"]) expect(out).toContain(`>${v}<`);
    expect(out.match(/coming soon/g)?.length).toBeGreaterThanOrEqual(3);
    expect(out).toContain('aria-pressed="true">Map<');
  });

  it("builds the land mask from compact embedded data", () => {
    expect(LAND_RLE).toHaveLength(LAND_ROWS);
    for (const row of LAND_RLE) {
      const total = row ? row.split(" ").reduce((a, n) => a + Number(n), 0) : 0;
      expect(total).toBeLessThanOrEqual(LAND_COLS);
    }
    expect(JSON.stringify(LAND_RLE).length).toBeLessThan(20_000);
    expect(landPath(["2 3"])).toBe("M8.3 0h12.5v4.2h-12.5z");
  });
});

describe("AppShell", () => {
  it("has the 12 nav items, count badges and an Australia (AU) region", () => {
    const out = html(
      <AppShell counts={{ "live-attacks": 37 }} exampleData>
        <p>child</p>
      </AppShell>,
    );
    expect(NAV_ITEMS).toHaveLength(12);
    for (const item of NAV_ITEMS) expect(out).toContain(item.label.replace("&", "&amp;"));
    expect(out).toContain("37");
    expect(out).toContain('aria-current="page"');
    expect(out).toContain('<option value="au" selected="">Australia (AU)</option>');
    expect(out).toContain("EXAMPLE DATA");
    expect(out).toContain("live__dot");
    expect(out).toContain("<p>child</p>");
  });
});
