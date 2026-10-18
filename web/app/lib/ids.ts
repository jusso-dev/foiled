/** Id formats the console accepts from URLs and forms before calling the API. Safe for the browser. */

export const ID_PATTERNS = {
  attempt: /^att_[a-f0-9]{24}$/,
  campaign: /^cmp_[a-f0-9]{24}$/,
  ioc: /^ioc_[a-f0-9]{24}$/,
  review: /^rq_[a-f0-9]{24}$/,
  writeup: /^wu_[a-f0-9]{24}$/,
  actorLink: /^acl_[a-f0-9]{24}$/,
  sha256: /^[a-f0-9]{64}$/,
  catalogue: /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._+-]*)+$/,
  /** Decoy, host, sensor and review item ids: opaque, but one path segment. */
  opaque: /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/,
} as const;

export type IdKind = keyof typeof ID_PATTERNS;

/** Thrown for an id that cannot be a valid API id; routes turn it into a 404. */
export class BadIdError extends Error {
  constructor(readonly kind: IdKind) {
    super(`invalid ${kind} id`);
    this.name = "BadIdError";
  }
}

export function isId(kind: IdKind, value: unknown): value is string {
  return typeof value === "string" && ID_PATTERNS[kind].test(value) && !value.includes("..");
}
