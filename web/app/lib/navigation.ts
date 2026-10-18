/** Small pure helpers for redirects and the console's jump box. */

/**
 * A post-sign-in destination taken from `?next=`. Only same-site paths are
 * allowed, so the login page can never be used as an open redirect.
 */
export function safeNext(next: string | null | undefined): string {
  if (!next || next.length > 1024) return "/";
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return "/";
  // Control characters could split a Location header or confuse a parser.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point.
  if (/[\u0000-\u001f\u007f]/.test(next)) return "/";
  if (next.startsWith("/login") || next.startsWith("/logout")) return "/";
  return next;
}

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:.]+$/i;

/**
 * Where the jump box sends a query: ids open their page, CVE and technique
 * ids filter attempts, addresses filter attempts by source, and anything
 * else searches IOCs by value (the API accepts defanged input).
 */
export function searchTarget(raw: string | null | undefined): string {
  const q = (raw ?? "").trim().slice(0, 256);
  if (!q) return "/";
  if (/^att_[a-f0-9]{24}$/.test(q)) return `/attempts/${q}`;
  if (/^cmp_[a-f0-9]{24}$/.test(q)) return `/campaigns/${q}`;
  if (/^ioc_[a-f0-9]{24}$/.test(q)) return `/iocs/${q}`;
  const enc = encodeURIComponent;
  if (/^(CVE-\d{4}-[A-Z0-9]+|FOILED-DEMO-\d+)$/i.test(q)) {
    return `/attempts?cve=${enc(q.toUpperCase())}`;
  }
  if (/^T\d{4}(\.\d{3})?$/i.test(q)) return `/attempts?technique=${enc(q.toUpperCase())}`;
  if (IPV4.test(q) || (q.includes(":") && IPV6.test(q))) return `/attempts?src=${enc(q)}`;
  return `/iocs?value=${enc(q)}`;
}
