/**
 * Per-client rate limit on the public surface (#35), using the Workers Rate
 * Limiting binding `PUBLIC_RATE_LIMIT` (wrangler.jsonc `env.public`). The
 * console has no binding and is never limited here; Access sits in front.
 */
import { clientIpFrom } from "./client-ip";

/** The part of the Workers rate limit binding we use. */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** Limit key: the client address, or one shared bucket when it is missing. */
export function rateLimitKey(request: Request): string {
  return clientIpFrom(request) ?? "unknown";
}

/**
 * True when the request is over the limit. No binding means no limit (the
 * console, tests, local dev). A failing binding lets the request through:
 * the API applies its own per-client limit behind this one.
 */
export async function isRateLimited(
  limiter: RateLimiter | undefined,
  key: string,
): Promise<boolean> {
  if (!limiter) return false;
  try {
    const { success } = await limiter.limit({ key });
    return !success;
  } catch {
    return false;
  }
}
