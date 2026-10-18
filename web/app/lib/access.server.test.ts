import { beforeAll, describe, expect, it } from "vitest";
import { type JwksFetcher, verifyAccess } from "./access.server";

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

describe("Cloudflare Access check", () => {
  it("is skipped when Access is not configured (local development)", async () => {
    expect(await verifyAccess(req(), {}, jwks, NOW)).toEqual({ ok: true });
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
