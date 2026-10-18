/**
 * Cloudflare Access check in the console Worker (docs/deploy/workers.md,
 * "Entry points and auth"). Access sits in front of the console hostname;
 * this repeats its check so a missing or misconfigured Access policy fails
 * closed. `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are required: without them
 * the console refuses every request, unless `CONSOLE_ENV` is `development`
 * (local development only; docs/ui/console.md#configuration).
 */

export interface AccessEnv {
  /** `development` lets the console run without Access, for local work only. */
  CONSOLE_ENV?: string;
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
/** An unknown `kid` refetches the keys at most this often per isolate. */
export const JWKS_REFRESH_MIN_MS = 60 * 1000;
const jwksCache = new Map<string, { at: number; keys: Jwk[] }>();

/** Test hook: forget cached keys. */
export function resetAccessCache(): void {
  jwksCache.clear();
}

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

async function fetchKeys(url: string, fetcher: JwksFetcher, now: number): Promise<Jwk[]> {
  const { keys } = await fetcher(url);
  const list = Array.isArray(keys) ? keys : [];
  jwksCache.set(url, { at: now, keys: list });
  return list;
}

/**
 * The signing key for `kid`. Keys are cached for 10 minutes. Access rotates
 * keys, so an unknown kid triggers a refetch, but at most once a minute per
 * isolate: within that minute every unknown kid is answered from the cached
 * miss, so a stream of forged kids cannot drive refetches.
 */
async function keyFor(team: string, kid: string, fetcher: JwksFetcher, now: number) {
  const url = `https://${team}/cdn-cgi/access/certs`;
  const hit = jwksCache.get(url);
  let keys = hit && now - hit.at < JWKS_TTL_MS ? hit.keys : await fetchKeys(url, fetcher, now);
  const jwk = keys.find((k) => k.kid === kid);
  if (jwk) return jwk;
  const lastFetch = jwksCache.get(url)?.at ?? 0;
  if (now - lastFetch < JWKS_REFRESH_MIN_MS) return undefined;
  keys = await fetchKeys(url, fetcher, now);
  return keys.find((k) => k.kid === kid);
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
  if (!team || !aud) {
    return env.CONSOLE_ENV === "development"
      ? { ok: true }
      : { ok: false, reason: "Access is not configured (ACCESS_TEAM_DOMAIN, ACCESS_AUD)" };
  }
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
    jwk = await keyFor(team, header.kid, fetcher, now);
  } catch {
    return { ok: false, reason: "Access keys unavailable" };
  }
  if (jwk?.kty !== "RSA") return { ok: false, reason: "unknown Access signing key" };
  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64urlBytes(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    // A malformed key or signature is a refusal, not a server error.
    return { ok: false, reason: "unusable Access signing key or signature" };
  }
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
