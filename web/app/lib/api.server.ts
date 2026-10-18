/**
 * Server-only client for the API Worker, reached over the `API` Service
 * Binding. The host part of the URL is ignored by Service Bindings; only the
 * path matters. The operator's bearer token is added here, on the Worker,
 * and never reaches the browser (docs/ui/console.md).
 */

import type {
  ActorDecision,
  ActorLinkRecord,
  AgentCreated,
  AgentRecord,
  AgentRevoked,
  Attempt,
  AttemptIocs,
  AttemptList,
  AttemptTimeline,
  AuditRecord,
  Campaign,
  CampaignAction,
  CampaignActionRequest,
  CampaignAttempts,
  CampaignEvidence,
  CampaignList,
  CampaignStub,
  CatalogueEntry,
  ConfidenceLink,
  CreateDecoy,
  Decoy,
  DecoyAction,
  Feedback,
  Ioc,
  IocList,
  JobAccepted,
  LinkKind,
  Page,
  Principal,
  QuarantineDownloadGrant,
  QuarantineDownloadRequest,
  QuarantineItem,
  RadarFeed,
  Reason,
  RegisterAgent,
  ReviewActionRequest,
  ReviewActionResult,
  ReviewList,
  WriteUp,
  WriteUpFields,
  WriteUpTransition,
  WriteUpVersion,
} from "./api-types";
import { BadIdError, type IdKind, isId } from "./ids";

export { BadIdError, ID_PATTERNS, type IdKind, isId } from "./ids";

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
    /** The API's `error.code`, when the body had one. */
    readonly code?: string,
    /** The API's `error.message`. Safe to show: it never holds internals. */
    readonly detail?: string,
  ) {
    super(`API ${path} returned ${status}`);
    this.name = "ApiError";
  }

  /** The route is in the spec but not served yet (planned), so the router fell through. */
  get notServed(): boolean {
    return (
      (this.status === 404 && this.code === "not_found" && this.detail === "route not found") ||
      this.status === 405
    );
  }
}

async function errorFrom(path: string, res: Response): Promise<ApiError> {
  let code: string | undefined;
  let detail: string | undefined;
  try {
    const body = (await res.json()) as { error?: { code?: unknown; message?: unknown } };
    if (typeof body?.error?.code === "string") code = body.error.code;
    if (typeof body?.error?.message === "string") detail = body.error.message.slice(0, 300);
  } catch {
    // Not JSON: keep the status only.
  }
  return new ApiError(path, res.status, code, detail);
}

/** Unauthenticated GET, for `/healthz`. */
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

// ---------- Path and query helpers ----------

/**
 * One path segment from an id taken from the URL or a form. Ids are checked
 * against their pattern first, so a crafted id can never walk to another API
 * route (`../audit`) or add a query string.
 */
export function seg(kind: IdKind, value: unknown): string {
  if (!isId(kind, value)) throw new BadIdError(kind);
  // Catalogue ids keep their slashes: the API takes them unescaped.
  return kind === "catalogue" ? value : encodeURIComponent(value);
}

export type QueryValue = string | number | boolean | null | undefined;

/** `?a=1&b=2`, skipping empty values. */
export function qs(params: Record<string, QueryValue>): string {
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    out.set(k, String(v));
  }
  const s = out.toString();
  return s ? `?${s}` : "";
}

/** Time window for attempt-derived reads. Passed through unchanged. */
export interface Window {
  since?: number;
  until?: number;
}

// ---------- Authenticated client ----------

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH";
  body?: unknown;
  idempotencyKey?: string;
  accept?: string;
}

/**
 * The console's view of the API, bound to one operator token. Tenant scoping
 * is the API's job: every call carries only the token, never a tenant id.
 */
export class ConsoleApi {
  constructor(
    private readonly api: ApiFetcher,
    private readonly token: string,
  ) {}

  /** Raw call. Throws ApiError on a non-2xx status. */
  async request(path: string, opts: RequestOptions = {}): Promise<Response> {
    const headers: Record<string, string> = {
      accept: opts.accept ?? "application/json",
      authorization: `Bearer ${this.token}`,
    };
    if (opts.body !== undefined) headers["content-type"] = "application/json";
    if (opts.idempotencyKey) headers["idempotency-key"] = opts.idempotencyKey;
    const res = await this.api.fetch(`${INTERNAL_ORIGIN}${path}`, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      redirect: "manual",
    });
    if (!res.ok) throw await errorFrom(path, res);
    return res;
  }

  async json<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    const res = await this.request(path, opts);
    return (await res.json()) as T;
  }

  async whoami(): Promise<Principal> {
    return this.json("/v0/whoami");
  }

  // Catalogue and decoys
  async listCatalogue(q: { decoy_kind?: string; status?: string; cve?: string } = {}) {
    return this.json<{ items: CatalogueEntry[] }>(`/v0/catalogue/entries${qs(q)}`);
  }
  async getCatalogueEntry(id: string) {
    return this.json<CatalogueEntry>(`/v0/catalogue/entries/${seg("catalogue", id)}`);
  }
  async listDecoys(q: { state?: string; live?: boolean; cursor?: string; limit?: number } = {}) {
    return this.json<Page<Decoy>>(`/v0/decoys${qs(q)}`);
  }
  async getDecoy(id: string) {
    return this.json<Decoy>(`/v0/decoys/${seg("opaque", id)}`);
  }
  async createDecoy(body: CreateDecoy, idempotencyKey: string) {
    return this.json<JobAccepted>("/v0/decoys", { method: "POST", body, idempotencyKey });
  }
  async decoyAction(id: string, action: DecoyAction, reason: Reason, idempotencyKey: string) {
    return this.json<JobAccepted>(`/v0/decoys/${seg("opaque", id)}:${action}`, {
      method: "POST",
      body: { reason },
      idempotencyKey,
    });
  }

  // Hosts and sensors
  async listAgents(role: "hosts" | "sensors", q: { cursor?: string; limit?: number } = {}) {
    return this.json<Page<AgentRecord>>(`/v0/${role}${qs(q)}`);
  }
  async registerAgent(role: "hosts" | "sensors", body: RegisterAgent) {
    return this.json<AgentCreated>(`/v0/${role}`, { method: "POST", body });
  }
  async revokeAgent(role: "hosts" | "sensors", id: string, reason: Reason) {
    return this.json<AgentRevoked>(`/v0/${role}/${seg("opaque", id)}:revoke`, {
      method: "POST",
      body: { reason },
    });
  }
  async reenrolAgent(role: "hosts" | "sensors", id: string, reason: Reason) {
    return this.json<AgentCreated>(`/v0/${role}/${seg("opaque", id)}:reenrol`, {
      method: "POST",
      body: { reason },
    });
  }

  // Attempts
  async listAttempts(q: Record<string, QueryValue>) {
    return this.json<AttemptList>(`/v0/attempts${qs(q)}`);
  }
  async getAttempt(id: string, w: Window = {}) {
    return this.json<Attempt>(`/v0/attempts/${seg("attempt", id)}${qs({ ...w })}`);
  }
  async getTimeline(id: string, w: Window = {}) {
    return this.json<AttemptTimeline>(`/v0/attempts/${seg("attempt", id)}/timeline${qs({ ...w })}`);
  }
  async getLinks(id: string, w: Window = {}) {
    return this.json<{ items: ConfidenceLink[] }>(
      `/v0/attempts/${seg("attempt", id)}/links${qs({ ...w })}`,
    );
  }
  async overrideLink(
    id: string,
    body: {
      kind: Exclude<LinkKind, "attempt_ioc">;
      target: string;
      feedback: Feedback;
      note: string;
    },
  ) {
    return this.json<ConfidenceLink>(`/v0/attempts/${seg("attempt", id)}/links`, {
      method: "POST",
      body,
    });
  }
  async getAttemptIocs(id: string, w: Window = {}) {
    return this.json<AttemptIocs>(`/v0/attempts/${seg("attempt", id)}/iocs${qs({ ...w })}`);
  }

  // IOCs
  async searchIocs(q: Record<string, QueryValue>) {
    return this.json<IocList>(`/v0/iocs${qs(q)}`);
  }
  async getIoc(id: string, w: Window = {}) {
    return this.json<Ioc>(`/v0/iocs/${seg("ioc", id)}${qs({ ...w })}`);
  }

  // Campaigns
  async listCampaigns(q: Record<string, QueryValue>) {
    return this.json<CampaignList>(`/v0/campaigns${qs(q)}`);
  }
  async getCampaign(id: string, w: Window = {}) {
    return this.json<Campaign | CampaignStub>(
      `/v0/campaigns/${seg("campaign", id)}${qs({ ...w })}`,
    );
  }
  async getCampaignAttempts(id: string, w: Window = {}) {
    return this.json<CampaignAttempts>(
      `/v0/campaigns/${seg("campaign", id)}/attempts${qs({ ...w })}`,
    );
  }
  async getCampaignEvidence(id: string, w: Window = {}) {
    return this.json<CampaignEvidence>(
      `/v0/campaigns/${seg("campaign", id)}/evidence${qs({ ...w })}`,
    );
  }
  async listCampaignActions(id: string) {
    return this.json<{ campaign_id: string; items: CampaignAction[] }>(
      `/v0/campaigns/${seg("campaign", id)}/actions`,
    );
  }
  async actOnCampaign(id: string, body: CampaignActionRequest, w: Window = {}) {
    return this.json<{ action: CampaignAction; campaign: Campaign | null }>(
      `/v0/campaigns/${seg("campaign", id)}/actions${qs({ ...w })}`,
      { method: "POST", body },
    );
  }

  // Review queue, write-ups and radar (#35). TODO(#35): not on main yet; shapes from PR #84.
  async listReview(q: Record<string, QueryValue> = {}) {
    return this.json<ReviewList>(`/v0/review-queue${qs(q)}`);
  }
  async actOnReview(id: string, body: ReviewActionRequest, w: Window = {}) {
    return this.json<ReviewActionResult>(
      `/v0/review-queue/${seg("review", id)}/actions${qs({ ...w })}`,
      { method: "POST", body },
    );
  }
  async listWriteUps(q: { status?: string; limit?: number } = {}) {
    return this.json<{ items: WriteUp[] }>(`/v0/write-ups${qs(q)}`);
  }
  async getWriteUp(id: string) {
    return this.json<WriteUp>(`/v0/write-ups/${seg("writeup", id)}`);
  }
  async createWriteUp(body: WriteUpFields) {
    return this.json<WriteUp>("/v0/write-ups", { method: "POST", body });
  }
  async editWriteUp(id: string, body: WriteUpFields) {
    return this.json<WriteUp>(`/v0/write-ups/${seg("writeup", id)}`, { method: "PATCH", body });
  }
  async transitionWriteUp(id: string, body: WriteUpTransition) {
    return this.json<WriteUp>(`/v0/write-ups/${seg("writeup", id)}/transitions`, {
      method: "POST",
      body,
    });
  }
  async listWriteUpVersions(id: string) {
    return this.json<{ writeup_id: string; items: WriteUpVersion[] }>(
      `/v0/write-ups/${seg("writeup", id)}/versions`,
    );
  }
  async getRadar(q: Record<string, QueryValue> = {}) {
    return this.json<RadarFeed>(`/v0/radar${qs(q)}`);
  }

  // Actor possible-associations (#29). TODO(#29): not on main yet; shapes from PR #83.
  async listActorLinks(q: Record<string, QueryValue> = {}) {
    return this.json<{ items: ActorLinkRecord[]; truncated: boolean }>(`/v0/actor-links${qs(q)}`);
  }
  async getActorLink(id: string, w: Window = {}) {
    return this.json<ActorLinkRecord>(`/v0/actor-links/${seg("actorLink", id)}${qs({ ...w })}`);
  }
  async decideActorLink(
    id: string,
    body: { decision: ActorDecision; note: string },
    w: Window = {},
  ) {
    return this.json<ActorLinkRecord>(
      `/v0/actor-links/${seg("actorLink", id)}/decision${qs({ ...w })}`,
      { method: "POST", body },
    );
  }

  // Quarantine. TODO(#9, #14): planned; see api-types.ts.
  async listQuarantine(q: { cursor?: string; limit?: number } = {}) {
    return this.json<Page<QuarantineItem>>(`/v0/quarantine${qs(q)}`);
  }
  async downloadQuarantine(sha256: string, body: QuarantineDownloadRequest) {
    return this.json<QuarantineDownloadGrant>(`/v0/quarantine/${seg("sha256", sha256)}:download`, {
      method: "POST",
      body,
    });
  }

  // Audit
  async listAudit(q: { action?: string; target?: string; cursor?: string; limit?: number } = {}) {
    return this.json<Page<AuditRecord>>(`/v0/audit${qs(q)}`);
  }

  /** An export download, returned as the raw response so it can be streamed on. */
  async exportDownload(path: string, q: Record<string, QueryValue>) {
    return this.request(`${path}${qs(q)}`, { accept: "*/*" });
  }
}
