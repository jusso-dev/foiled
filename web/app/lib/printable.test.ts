import { describe, expect, it } from "vitest";
import { toPrintable } from "./printable";

describe("toPrintable", () => {
  it("escapes controls, bidi, zero-width and line separators", () => {
    expect(toPrintable("a\rb")).toBe("a\\x0db");
    expect(toPrintable("x‮y")).toBe("x\\u{202e}y");
    for (const ch of ["​", "‍", "﻿", " ", " ", "؜", "⁠"]) {
      expect(toPrintable(`a${ch}b`)).not.toContain(ch);
    }
    expect(toPrintable("plain\ttext\nok")).toBe("plain\ttext\nok");
  });
});
