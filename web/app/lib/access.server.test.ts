import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  JWKS_REFRESH_MIN_MS,
  type JwksFetcher,
  resetAccessCache,
  verifyAccess,
} from "./access.server";

const TEAM = "example.cloudflareaccess.com";
const AUD = "aud-tag-0001";
const NOW = 1_800_000_000_000;
const env = { ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD };

let keys: CryptoKeyPair;
let jwks: JwksFetcher;

const b64url = (b: Uint8Array | string) => {
  const bytes = typeof b === "string" ? new TextEncoder().encode(b) : b;
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

async function sign(claims: Record<string, unknown>, kid = "k1", key = keys.privateKey) {
  const head = b64url(JSON.stringify({ alg: "RS256", kid, typ: "JWT" }));
  const body = b64url(JSON.stringify(claims));
  const sig = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${body}`)),
  );
  return `${head}.${body}.${b64url(sig)}`;
}

const good = {
  aud: [AUD],
  iss: `https://${TEAM}`,
  exp: NOW / 1000 + 600,
  nbf: NOW / 1000 - 10,
  email: "analyst@example.invalid",
};
const req = (jwt?: string) =>
  new Request("https://console.test/", { headers: jwt ? { "cf-access-jwt-assertion": jwt } : {} });

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pub = (await crypto.subtle.exportKey("jwk", keys.publicKey)) as JsonWebKey;
  jwks = async (url) => {
    expect(url).toBe(`https://${TEAM}/cdn-cgi/access/certs`);
    return { keys: [{ kid: "k1", kty: "RSA", n: pub.n as string, e: pub.e as string }] };
  };
});

beforeEach(() => resetAccessCache());

describe("Cloudflare Access check", () => {
  it("refuses every request when Access is not configured, except in explicit development mode", async () => {
    expect((await verifyAccess(req(), {}, jwks, NOW)).ok).toBe(false);
    expect((await verifyAccess(req(), { ACCESS_AUD: AUD }, jwks, NOW)).ok).toBe(false);
    expect((await verifyAccess(req(), { CONSOLE_ENV: "production" }, jwks, NOW)).ok).toBe(false);
    expect(await verifyAccess(req(), { CONSOLE_ENV: "development" }, jwks, NOW)).toEqual({
      ok: true,
    });
  });

  it("refetches keys for an unknown kid at most once a minute and remembers misses", async () => {
    let calls = 0;
    const counting: JwksFetcher = async (url) => {
      calls++;
      return jwks(url);
    };
    const forged = await sign(good, "k-forged");
    expect((await verifyAccess(req(await sign(good)), env, counting, NOW)).ok).toBe(true);
    expect(calls).toBe(1);
    for (let i = 0; i < 20; i++) {
      expect((await verifyAccess(req(forged), env, counting, NOW + i * 1000)).ok).toBe(false);
    }
    expect(calls).toBe(1);
    // After the minute: one refetch, then the miss is cached again.
    const later = NOW + JWKS_REFRESH_MIN_MS + 1;
    await verifyAccess(req(forged), env, counting, later);
    await verifyAccess(req(forged), env, counting, later + 1);
    expect(calls).toBe(2);
  });

  it("answers a malformed signing key or signature with a refusal, not an exception", async () => {
    // A JWK the runtime refuses to import (workerd is stricter than Node here).
    const spy = vi
      .spyOn(crypto.subtle, "importKey")
      .mockRejectedValueOnce(new DOMException("bad key"));
    expect(await verifyAccess(req(await sign(good)), env, jwks, NOW)).toEqual({
      ok: false,
      reason: "unusable Access signing key or signature",
    });
    spy.mockRestore();
    resetAccessCache();
    const jwt = (await sign(good)).replace(/\.[^.]+$/, ".***");
    expect((await verifyAccess(req(jwt), env, jwks, NOW)).ok).toBe(false);
  });

  it("accepts a valid token", async () => {
    expect(await verifyAccess(req(await sign(good)), env, jwks, NOW)).toEqual({
      ok: true,
      email: "analyst@example.invalid",
    });
  });

  it("fails closed on missing, forged, foreign, expired or unknown-key tokens", async () => {
    const other = (await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const cases: [string, string | undefined][] = [
      ["missing", undefined],
      ["junk", "a.b.c"],
      ["forged", await sign(good, "k1", other.privateKey)],
      ["audience", await sign({ ...good, aud: ["someone-else"] })],
      ["issuer", await sign({ ...good, iss: "https://evil.example" })],
      ["expired", await sign({ ...good, exp: NOW / 1000 - 1 })],
      ["kid", await sign(good, "k9")],
    ];
    for (const [name, jwt] of cases) {
      expect((await verifyAccess(req(jwt), env, jwks, NOW)).ok, name).toBe(false);
    }
  });

  it("refuses tokens that are not RS256", async () => {
    const head = b64url(JSON.stringify({ alg: "none", kid: "k1" }));
    const jwt = `${head}.${b64url(JSON.stringify(good))}.`;
    expect(await verifyAccess(req(jwt), env, jwks, NOW)).toEqual({
      ok: false,
      reason: "unexpected Access token algorithm",
    });
  });
});
