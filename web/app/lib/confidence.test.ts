import { describe, expect, it } from "vitest";
import { confidenceFromLink } from "./confidence";

describe("confidenceFromLink", () => {
  it("only shows Confirmed after an analyst confirms", () => {
    expect(confidenceFromLink({ score: 100, band: "high", wording: "we assess as" }).level).toBe(
      "probable",
    );
    expect(confidenceFromLink({ score: 100, band: "high", wording: "confirmed" }).level).toBe(
      "confirmed",
    );
  });

  it("maps low and medium bands to Assessed and keeps the score", () => {
    expect(confidenceFromLink({ score: 40, band: "medium", wording: "we assess as" })).toEqual({
      level: "assessed",
      score: 40,
    });
    expect(confidenceFromLink({ score: 12, band: "low", wording: "we assess as" }).level).toBe(
      "assessed",
    );
  });
});
