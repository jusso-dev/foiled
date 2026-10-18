/**
 * Cloudflare Access check in the console Worker (docs/deploy/workers.md,
 * "Entry points and auth"). Access sits in front of the console hostname;
 * this repeats its check so a missing or misconfigured Access policy fails
 * closed. Enforced when `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are both set.
 */

export interface AccessEnv {
  /** For example `example.cloudflareaccess.com`. */
  ACCESS_TEAM_DOMAIN?: string;
  /** The Access application's audience tag. */
  ACCESS_AUD?: string;
}

interface Jwk {
  kid: string;
  kty: string;
  n: string;
  e: string;
  alg?: string;
}

export type JwksFetcher = (url: string) => Promise<{ keys: Jwk[] }>;

const JWKS_TTL_MS = 10 * 60 * 1000;
const jwksCache = new Map<string, { at: number; keys: Jwk[] }>();

const defaultFetcher: JwksFetcher = async (url) => {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`JWKS ${res.status}`);
  return (await res.json()) as { keys: Jwk[] };
};

function b64urlBytes(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlJson(s: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlBytes(s))) as Record<string, unknown>;
}

async function keysFor(team: string, fetcher: JwksFetcher, now: number, refresh: boolean) {
  const url = `https://${team}/cdn-cgi/access/certs`;
  const hit = jwksCache.get(url);
  if (hit && !refresh && now - hit.at < JWKS_TTL_MS) return hit.keys;
  const { keys } = await fetcher(url);
  jwksCache.set(url, { at: now, keys: Array.isArray(keys) ? keys : [] });
  return jwksCache.get(url)?.keys ?? [];
}

export type AccessResult = { ok: true; email?: string } | { ok: false; reason: string };

/** Verify the `Cf-Access-Jwt-Assertion` header: RS256 signature, issuer, audience and time. */
export async function verifyAccess(
  request: Request,
  env: AccessEnv,
  fetcher: JwksFetcher = defaultFetcher,
  now = Date.now(),
): Promise<AccessResult> {
  const team = env.ACCESS_TEAM_DOMAIN?.trim();
  const aud = env.ACCESS_AUD?.trim();
  if (!team || !aud) return { ok: true };
  const jwt = request.headers.get("cf-access-jwt-assertion");
  if (!jwt || jwt.length > 8192) return { ok: false, reason: "missing Access token" };
  const parts = jwt.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed Access token" };
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = b64urlJson(parts[0]);
    claims = b64urlJson(parts[1]);
  } catch {
    return { ok: false, reason: "malformed Access token" };
  }
  if (header.alg !== "RS256" || typeof header.kid !== "string") {
    return { ok: false, reason: "unexpected Access token algorithm" };
  }
  let jwk: Jwk | undefined;
  try {
    jwk = (await keysFor(team, fetcher, now, false)).find((k) => k.kid === header.kid);
    // Access rotates keys: one refresh when the kid is unknown.
    if (!jwk) jwk = (await keysFor(team, fetcher, now, true)).find((k) => k.kid === header.kid);
  } catch {
    return { ok: false, reason: "Access keys unavailable" };
  }
  if (jwk?.kty !== "RSA") return { ok: false, reason: "unknown Access signing key" };
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) return { ok: false, reason: "bad Access token signature" };
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(aud)) return { ok: false, reason: "Access token for another application" };
  if (claims.iss !== `https://${team}`)
    return { ok: false, reason: "Access token from another team" };
  const sec = Math.floor(now / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= sec) {
    return { ok: false, reason: "expired Access token" };
  }
  if (typeof claims.nbf === "number" && claims.nbf > sec + 60) {
    return { ok: false, reason: "Access token not yet valid" };
  }
  return { ok: true, email: typeof claims.email === "string" ? claims.email : undefined };
}
