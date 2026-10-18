/**
 * The visitor's address on the public surface (#35), from the
 * CF-Connecting-IP header Cloudflare sets on every request. Used as the rate
 * limit key and forwarded to the API for its own per-client limit. Never
 * shown on a page.
 */

/** Characters of an IPv4 or IPv6 address as Cloudflare writes it. */
const IP_PATTERN = /^[0-9A-Fa-f:.]{2,45}$/;

export function isIpLike(value: string): boolean {
  return IP_PATTERN.test(value);
}

/** The client address, or null when the header is absent or not an address. */
export function clientIpFrom(request: Request): string | null {
  const ip = request.headers.get("CF-Connecting-IP");
  return ip && isIpLike(ip) ? ip : null;
}
