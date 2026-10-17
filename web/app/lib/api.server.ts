/**
 * Thin client for the API Worker, reached over the `API` Service Binding.
 * The host part of the URL is ignored by Service Bindings; only the path matters.
 */

export interface Health {
  status: string;
  service: string;
  version: string;
}

export type ApiFetcher = Pick<Fetcher, "fetch">;

const INTERNAL_ORIGIN = "https://api.internal";

export class ApiError extends Error {
  constructor(
    readonly path: string,
    readonly status: number,
  ) {
    super(`API ${path} returned ${status}`);
    this.name = "ApiError";
  }
}

export async function apiJson<T>(api: ApiFetcher, path: string): Promise<T> {
  const res = await api.fetch(`${INTERNAL_ORIGIN}${path}`, {
    headers: { accept: "application/json" },
  });
  if (!res.ok) {
    throw new ApiError(path, res.status);
  }
  return (await res.json()) as T;
}

function isHealth(value: unknown): value is Health {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.status === "string" && typeof v.service === "string" && typeof v.version === "string"
  );
}

/** Ask the API Worker for its health. Returns null when it is unreachable or malformed. */
export async function getHealth(api: ApiFetcher): Promise<Health | null> {
  try {
    const body = await apiJson<unknown>(api, "/healthz");
    return isHealth(body) ? body : null;
  } catch {
    return null;
  }
}
