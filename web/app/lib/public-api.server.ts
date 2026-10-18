/**
 * Client for the unauthenticated public API routes (#35), reached over the
 * `API` Service Binding. It only ever calls paths under `/v0/public/`, so a
 * bug in a public page cannot reach a tenant or console route. The radar is
 * trusted-side only and has no public route.
 *
 * Types are in public-types.ts. Every string the API returns is
 * attacker-influenced: render with toPrintable.
 */
import { ApiError, type ApiFetcher } from "./api.server";
import { clientIpFrom, isIpLike } from "./client-ip";
import {
  type PublicAssessment,
  type PublicExploitList,
  type PublicExploitListItem,
  type PublicExploitPage,
  SLUG_PATTERN,
} from "./public-types";

export * from "./public-types";
export { clientIpFrom };

export const PUBLIC_API_PREFIX = "/v0/public/";

const INTERNAL_ORIGIN = "https://api.internal";

/** Thrown for a path outside `/v0/public/`. A programming error, never user input. */
export class PublicPathError extends Error {
  constructor(readonly path: string) {
    super("Refusing to call a non-public API path from a public page");
    this.name = "PublicPathError";
  }
}

/** Thrown when an API body does not have the shape the schema promises. */
export class PublicShapeError extends Error {
  constructor(readonly path: string) {
    super(`API ${path} returned an unexpected shape`);
    this.name = "PublicShapeError";
  }
}

/**
 * Resolve `path` against the internal origin and check the result is still
 * under `/v0/public/`. Resolving first catches `..`, `%2e%2e` and backslash
 * tricks that a plain prefix check would miss.
 */
export function publicApiUrl(path: string): URL {
  if (!path.startsWith(PUBLIC_API_PREFIX)) throw new PublicPathError(path);
  let url: URL;
  try {
    url = new URL(path, INTERNAL_ORIGIN);
  } catch {
    throw new PublicPathError(path);
  }
  if (url.origin !== INTERNAL_ORIGIN || !url.pathname.startsWith(PUBLIC_API_PREFIX)) {
    throw new PublicPathError(path);
  }
  return url;
}

/** Header the API reads for its own per-client rate limit on public routes. */
export const CLIENT_IP_HEADER = "X-Foiled-Client-Ip";

export interface PublicRequestOptions {
  /** Visitor address from CF-Connecting-IP, forwarded so the API can limit per client. */
  clientIp?: string | null;
}

/** GET a public API path. Returns null on 404 and throws ApiError on any other failure. */
async function publicJson(
  api: ApiFetcher,
  path: string,
  { clientIp }: PublicRequestOptions = {},
): Promise<unknown | null> {
  const url = publicApiUrl(path);
  const headers: Record<string, string> = { accept: "application/json" };
  if (clientIp && isIpLike(clientIp)) headers[CLIENT_IP_HEADER] = clientIp;
  const res = await api.fetch(url.href, { headers });
  if (res.status === 404) return null;
  if (!res.ok) throw new ApiError(path, res.status);
  return res.json();
}

// Light runtime shape checks. The API is ours, but a public page should fail
// closed on a body it does not understand rather than render half of it.
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
const isStr = (v: unknown): v is string => typeof v === "string";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isArr = Array.isArray;

function isAssessment(v: unknown): v is PublicAssessment {
  return isObj(v) && isStr(v.id) && (v.wording === "we assess as" || v.wording === "confirmed");
}

function isListItem(v: unknown): v is PublicExploitListItem {
  return (
    isObj(v) &&
    isStr(v.slug) &&
    isStr(v.canonical_path) &&
    isStr(v.title) &&
    isStr(v.summary) &&
    isNum(v.visible_from) &&
    isArr(v.cves) &&
    v.cves.every(isAssessment)
  );
}

export function isPublicExploitList(v: unknown): v is PublicExploitList {
  return isObj(v) && isArr(v.items) && v.items.every(isListItem);
}

export function isPublicExploitPage(v: unknown): v is PublicExploitPage {
  return (
    isObj(v) &&
    isStr(v.slug) &&
    isStr(v.canonical_path) &&
    isStr(v.title) &&
    isStr(v.summary) &&
    isArr(v.body) &&
    v.tlp === "clear" &&
    isNum(v.published_at) &&
    isNum(v.visible_from) &&
    isNum(v.version) &&
    isArr(v.cves) &&
    v.cves.every(isAssessment) &&
    isArr(v.techniques) &&
    v.techniques.every(isAssessment) &&
    isArr(v.timeline) &&
    (v.redacted_payload === null || isStr(v.redacted_payload)) &&
    isArr(v.iocs)
  );
}

/**
 * Upper bounds on what a page renders. The API caps the list at 100 pages
 * and keeps write-ups small; these caps make sure the web never loops over
 * more than that even if a body grows.
 */
export const LIMITS = {
  listItems: 100,
  blocks: 1000,
  assessments: 100,
  timeline: 50,
  iocs: 500,
} as const;

const cap = <T>(v: unknown, n: number): T[] =>
  Array.isArray(v) ? (v.slice(0, n) as T[]) : (v as T[]);

/** Published, visible exploit pages, newest first, at most LIMITS.listItems. */
export async function getPublicExploitList(
  api: ApiFetcher,
  options?: PublicRequestOptions,
): Promise<PublicExploitList> {
  const path = `${PUBLIC_API_PREFIX}exploited`;
  const body = await publicJson(api, path, options);
  if (body === null) return { items: [] };
  if (isObj(body)) body.items = cap(body.items, LIMITS.listItems);
  if (!isPublicExploitList(body)) throw new PublicShapeError(path);
  return body;
}

/** One exploit page, or null when it is not published or not yet visible. */
export async function getPublicExploitPage(
  api: ApiFetcher,
  slug: string,
  options?: PublicRequestOptions,
): Promise<PublicExploitPage | null> {
  // An invalid slug can never be a published page, so do not ask the API.
  if (slug.length > 80 || !SLUG_PATTERN.test(slug)) return null;
  const path = `${PUBLIC_API_PREFIX}exploited/${slug}`;
  const body = await publicJson(api, path, options);
  if (body === null) return null;
  if (isObj(body)) {
    body.body = cap(body.body, LIMITS.blocks);
    body.cves = cap(body.cves, LIMITS.assessments);
    body.techniques = cap(body.techniques, LIMITS.assessments);
    body.timeline = cap(body.timeline, LIMITS.timeline);
    body.iocs = cap(body.iocs, LIMITS.iocs);
  }
  if (!isPublicExploitPage(body)) throw new PublicShapeError(path);
  return body;
}
