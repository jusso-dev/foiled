import { describe, expect, it } from "vitest";
import { AA_LARGE, AA_TEXT, contrastRatio, hexToRgb, relativeLuminance } from "./contrast";

// v3 palette values (docs/design/design-direction.md).
const bg = "#07080A";
const panel = "#101216";
const muted = "#8A9099";
const dim = "#5B616B";

describe("relative luminance", () => {
  it("is 0 for black and 1 for white", () => {
    expect(relativeLuminance("#000000")).toBe(0);
    expect(relativeLuminance("#FFFFFF")).toBeCloseTo(1, 10);
  });

  it("parses short and long hex", () => {
    expect(hexToRgb("#fff")).toEqual([255, 255, 255]);
    expect(hexToRgb("E5252A")).toEqual([229, 37, 42]);
    expect(() => hexToRgb("red")).toThrow();
  });
});

describe("contrast ratio", () => {
  it("matches the WCAG reference points", () => {
    expect(contrastRatio("#000000", "#FFFFFF")).toBeCloseTo(21, 5);
    expect(contrastRatio("#777777", "#FFFFFF")).toBeCloseTo(4.48, 2);
    expect(contrastRatio("#FFFFFF", "#000000")).toBe(contrastRatio("#000000", "#FFFFFF"));
  });

  // Recorded in docs/ui/design-system.md. Update both if the palette changes.
  it("muted passes AA body text on panel and bg", () => {
    expect(contrastRatio(muted, panel)).toBeCloseTo(5.83, 2);
    expect(contrastRatio(muted, bg)).toBeCloseTo(6.23, 2);
    expect(contrastRatio(muted, panel)).toBeGreaterThanOrEqual(AA_TEXT);
    expect(contrastRatio(muted, bg)).toBeGreaterThanOrEqual(AA_TEXT);
  });

  it("dim fails AA body text, so it is limited to large text and decoration", () => {
    expect(contrastRatio(dim, panel)).toBeCloseTo(3.01, 2);
    expect(contrastRatio(dim, bg)).toBeCloseTo(3.21, 2);
    expect(contrastRatio(dim, panel)).toBeLessThan(AA_TEXT);
    expect(contrastRatio(dim, panel)).toBeGreaterThanOrEqual(AA_LARGE);
    expect(contrastRatio(dim, bg)).toBeGreaterThanOrEqual(AA_LARGE);
  });

  it("the focus ring (red-bright) meets 3:1 against panel and bg", () => {
    expect(contrastRatio("#FF3B3F", panel)).toBeGreaterThanOrEqual(AA_LARGE);
    expect(contrastRatio("#FF3B3F", bg)).toBeGreaterThanOrEqual(AA_LARGE);
  });

  it("text colours used for small text pass AA on panel", () => {
    for (const fg of ["#E6E8EB", "#C9CDD3", "#FF3B3F", "#F2A93B", "#7FC4F0", "#3FB68B"]) {
      expect(contrastRatio(fg, panel), fg).toBeGreaterThanOrEqual(AA_TEXT);
    }
  });
});
