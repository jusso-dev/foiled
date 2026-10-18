/**
 * Source rules that keep the operator's token on the Worker
 * (docs/ui/console.md#sign-in-and-sessions). React Router strips loaders,
 * actions and `.server` modules from the browser bundle; these checks make
 * sure nothing else reaches for the token or browser storage.
 */

import { describe, expect, it } from "vitest";

const sources = import.meta.glob(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../test/**"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

/** Code without comments, so docs that name a rule do not trip it. */
const code = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

describe("client safety", () => {
  it("scans the console sources", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(40);
  });

  it("never uses browser storage or reads cookies from script", () => {
    for (const [file, src] of Object.entries(sources)) {
      expect(code(src), file).not.toMatch(/\b(localStorage|sessionStorage|indexedDB)\b/);
      expect(code(src), file).not.toMatch(/document\.cookie/);
    }
  });

  it("builds the Authorization header only in the server-only API client", () => {
    for (const [file, src] of Object.entries(sources)) {
      if (file.endsWith("api.server.ts")) continue;
      expect(code(src), file).not.toMatch(/authorization["']?\s*:/i);
      expect(code(src), file).not.toMatch(/Bearer \$\{/);
    }
  });

  it("touches the session secret and token only in server modules and route loaders or actions", () => {
    for (const [file, src] of Object.entries(sources)) {
      if (file.endsWith(".server.ts") || file.endsWith("/env.d.ts")) continue;
      if (file.includes("/routes/")) {
        // Routes may read it in loaders and actions, which never ship to the browser.
        const component = src.slice(src.indexOf("export default function"));
        expect(component, file).not.toMatch(/env\.SESSION_SECRET/);
        expect(component, file).not.toMatch(/session\.token/);
        continue;
      }
      expect(code(src), file).not.toMatch(/env\.SESSION_SECRET/);
    }
  });

  it("imports server modules only from routes and other server modules", () => {
    for (const [file, src] of Object.entries(sources)) {
      if (file.endsWith(".server.ts") || file.includes("/routes/") || file.endsWith("/root.tsx")) {
        continue;
      }
      expect(src, file).not.toMatch(/from "[^"]*\.server"/);
    }
  });
});
