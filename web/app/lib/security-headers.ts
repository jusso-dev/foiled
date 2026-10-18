/**
 * Response headers for every console response. The console is a trusted,
 * signed-in interface: it is never framed, never cached by shared caches and
 * never sends a referrer that could carry an attempt or campaign id away.
 *
 * The CSP leaves `script-src` to a later change: React Router's hydration
 * script is inline and would need a per-request nonce.
 */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "content-security-policy":
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

export function withSecurityHeaders(res: Response): Response {
  // Redirects and some fetch responses have immutable headers; copy first.
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    if (!out.headers.has(k)) out.headers.set(k, v);
  }
  // Pages and data can hold attempt details and the CSRF token: never store them.
  if (!out.headers.has("cache-control")) out.headers.set("cache-control", "no-store");
  return out;
}
