import { describe, expect, it } from "vitest";
import designDirection from "../../../docs/design/design-direction.md?raw";
import base from "./base.css?raw";
import components from "./components.css?raw";
import tokens from "./tokens.css?raw";

const componentSources = import.meta.glob("../components/**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;
const routeSources = import.meta.glob("../routes/**/*.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Palette rows from the v3 table: `| \`name\` | \`#RRGGBB\` ... |`. */
function v3Palette(): Map<string, string> {
  const v3 = designDirection.slice(designDirection.indexOf("## v3"));
  const table = v3.slice(v3.indexOf("### Palette"), v3.indexOf("### Type"));
  const out = new Map<string, string>();
  for (const m of table.matchAll(/^\| `([a-z0-9-]+)` \| `(#[0-9A-Fa-f]{6})`/gm)) {
    out.set(m[1], m[2]);
  }
  return out;
}

/** `--name: value;` declarations in tokens.css. Hex case is ignored (Biome lowercases it). */
function tokenValues(): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of tokens.matchAll(/^\s*--([a-z0-9-]+):\s*([^;]+);/gm)) {
    out.set(m[1], m[2].trim().toUpperCase());
  }
  return out;
}

describe("tokens.css", () => {
  const values = tokenValues();

  it("matches every single-colour token in the v3 palette table", () => {
    const palette = v3Palette();
    expect(palette.size).toBeGreaterThanOrEqual(15);
    for (const [name, hex] of palette) {
      expect(values.get(name), `--${name}`).toBe(hex.toUpperCase());
    }
  });

  it("uses the exact palette names and values from the issue", () => {
    const expected = {
      bg: "#07080A",
      side: "#0B0C0F",
      panel: "#101216",
      "panel-2": "#14171C",
      line: "#1F232A",
      "line-2": "#2A2F37",
      text: "#E6E8EB",
      muted: "#8A9099",
      dim: "#5B616B",
      red: "#E5252A",
      "red-bright": "#FF3B3F",
      "red-deep": "#3A0D0F",
      amber: "#F2A93B",
      blue: "#4C8DF6",
      green: "#3FB68B",
    };
    for (const [name, hex] of Object.entries(expected)) {
      expect(values.get(name), `--${name}`).toBe(hex);
    }
    expect(tokens).toContain("--focus-ring: 2px solid var(--red-bright);");
  });
});

describe("visual rules", () => {
  const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "");
  const css = stripComments(`${tokens}\n${base}\n${components}`);

  it("has no glowing text and no scanlines", () => {
    expect(css).not.toMatch(/text-shadow/);
    expect(css).not.toMatch(/scanline/i);
    expect(css).not.toMatch(/repeating-linear-gradient/);
  });

  it("uses glow only on the live indicator", () => {
    const glowUses = [...components.matchAll(/([^{}]+)\{[^}]*var\(--glow-live\)[^}]*\}/g)].map(
      (m) => m[1].trim(),
    );
    expect(glowUses).toHaveLength(1);
    expect(glowUses[0]).toMatch(/live__dot/);
    // Every other box-shadow is a hard inset rule (the active nav item).
    for (const m of components.matchAll(/box-shadow:\s*([^;]+);/g)) {
      expect(m[1] === "var(--glow-live)" || m[1].startsWith("inset 3px 0 0")).toBe(true);
    }
  });

  it("uses the SVG blur filter only on map hotspots and sensors", () => {
    for (const [file, src] of Object.entries({ ...componentSources, ...routeSources })) {
      if (file.endsWith("AttackMap.tsx")) continue;
      expect(src, file).not.toContain("feGaussianBlur");
    }
  });

  it("shows a visible focus outline on interactive elements", () => {
    expect(base).toMatch(/:focus-visible\s*\{\s*outline: var\(--focus-ring\)/);
    expect(base).toMatch(/button:focus-visible/);
    expect(base).toMatch(/select:focus-visible/);
  });
});

describe("attacker text safety", () => {
  it("no component or route uses dangerouslySetInnerHTML", () => {
    const all = { ...componentSources, ...routeSources };
    expect(Object.keys(all).length).toBeGreaterThan(10);
    for (const [file, src] of Object.entries(all)) {
      if (file.endsWith(".test.tsx")) continue;
      expect(src, file).not.toContain("dangerouslySetInnerHTML");
    }
  });

  it("only CveRef renders CVE id styling", () => {
    for (const [file, src] of Object.entries(componentSources)) {
      if (file.endsWith("CveRef.tsx") || file.endsWith(".test.tsx")) continue;
      expect(src, file).not.toContain("cve-ref__id");
    }
  });
});
