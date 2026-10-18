import { describe, expect, it } from "vitest";
import type { Principal } from "./api-types";
import {
  clearSessionCookie,
  hasScope,
  newSession,
  openSession,
  readCookie,
  SESSION_TTL_MS,
  SessionConfigError,
  safeEqual,
  sameOrigin,
  sealSession,
  sessionCookie,
} from "./session.server";

const SECRET = "unit-test-secret-0123456789abcdef-xyz";
const P: Principal = { id: "tok1", role: "human", tenant_id: "t1", scopes: ["attempts:read"] };
const NOW = 1_800_000_000_000;
const TOKEN = `fo_tok1.${"b".repeat(40)}`;

describe("session cookie", () => {
  it("round-trips and hides the token", async () => {
    const s = newSession(TOKEN, P, NOW);
    const sealed = await sealSession(s, SECRET);
    expect(sealed).not.toContain("tok1");
    expect(
      atob(
        sealed
          .replace(/-/g, "+")
          .replace(/_/g, "/")
          .padEnd(Math.ceil(sealed.length / 4) * 4, "="),
      ),
    ).not.toContain(TOKEN);
    expect(await openSession(sealed, SECRET, NOW + 1000)).toEqual(s);
  });

  it("uses a fresh IV, so the same session seals differently", async () => {
    const s = newSession(TOKEN, P, NOW);
    expect(await sealSession(s, SECRET)).not.toBe(await sealSession(s, SECRET));
  });

  it("rejects tampering, another key, expiry and junk", async () => {
    const s = newSession(TOKEN, P, NOW);
    const sealed = await sealSession(s, SECRET);
    const flipped = sealed.slice(0, 20) + (sealed[20] === "A" ? "B" : "A") + sealed.slice(21);
    expect(await openSession(flipped, SECRET, NOW)).toBeNull();
    expect(await openSession(sealed, `${SECRET}-other`, NOW)).toBeNull();
    expect(await openSession(sealed, SECRET, NOW + SESSION_TTL_MS)).toBeNull();
    expect(await openSession("not base64!", SECRET, NOW)).toBeNull();
    expect(await openSession("", SECRET, NOW)).toBeNull();
    expect(await openSession("A".repeat(5000), SECRET, NOW)).toBeNull();
  });

  it("refuses to work without a long enough secret", async () => {
    const s = newSession(TOKEN, P, NOW);
    await expect(sealSession(s, "short")).rejects.toBeInstanceOf(SessionConfigError);
    await expect(sealSession(s, undefined)).rejects.toBeInstanceOf(SessionConfigError);
  });

  it("sets httpOnly, Secure, SameSite=Strict and a __Host- name", () => {
    const c = sessionCookie("v", 3600_000);
    expect(c).toBe(
      "__Host-foiled_session=v; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600",
    );
    expect(clearSessionCookie()).toContain("Max-Age=0");
  });

  it("reads one cookie among several", () => {
    expect(readCookie("a=1; __Host-foiled_session=xyz; b=2", "__Host-foiled_session")).toBe("xyz");
    expect(readCookie("a=1", "__Host-foiled_session")).toBeNull();
    expect(readCookie(null, "x")).toBeNull();
  });

  it("gives each session its own CSRF token", () => {
    expect(newSession(TOKEN, P, NOW).csrf).not.toBe(newSession(TOKEN, P, NOW).csrf);
    expect(newSession(TOKEN, P, NOW).csrf).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("request checks", () => {
  const req = (headers: Record<string, string>) =>
    new Request("https://console.test/x", { method: "POST", headers });

  it("accepts same-origin posts and refuses cross-site ones", () => {
    expect(sameOrigin(req({ origin: "https://console.test" }))).toBe(true);
    expect(
      sameOrigin(req({ origin: "https://console.test", "sec-fetch-site": "same-origin" })),
    ).toBe(true);
    expect(sameOrigin(req({ origin: "https://evil.example" }))).toBe(false);
    expect(
      sameOrigin(req({ origin: "https://console.test", "sec-fetch-site": "cross-site" })),
    ).toBe(false);
    expect(sameOrigin(req({ "sec-fetch-site": "same-site" }))).toBe(false);
    expect(sameOrigin(req({}))).toBe(false);
    expect(sameOrigin(req({ origin: "null" }))).toBe(false);
  });

  it("compares CSRF tokens in full", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
    expect(safeEqual("", "a")).toBe(false);
  });

  it("treats admin as every operator scope", () => {
    expect(hasScope(P, "attempts:read")).toBe(true);
    expect(hasScope(P, "attempts:write")).toBe(false);
    expect(hasScope({ ...P, scopes: ["admin"] }, "review:write")).toBe(true);
  });
});
