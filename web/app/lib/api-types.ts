/**
 * Types for the control plane API (api/openapi.yaml), written from the JSON
 * Schemas under schemas/. `api-types.test.ts` compares the keys of each type
 * with its schema so the two cannot drift apart silently.
 *
 * Fields marked "hostile" carry attacker-controlled text. Render them through
 * `toPrintable` as text children only.
 */

export type Scope =
  | "catalogue:read"
  | "decoys:read"
  | "decoys:write"
  | "decoys:elevate"
  | "attempts:read"
  | "attempts:write"
  | "campaigns:read"
  | "campaigns:write"
  | "iocs:read"
  | "review:read"
  | "review:write"
  | "sensors:read"
  | "sensors:write"
  | "hosts:read"
  | "hosts:write"
  | "quarantine:read"
  | "quarantine:download"
  | "exports:read"
  | "alerts:read"
  | "alerts:write"
  | "audit:read"
  | "events:read"
  | "admin";

/** `GET /v0/whoami`. */
export interface Principal {
  id: string;
  role: "human" | "mcp" | "host" | "sensor";
  tenant_id: string;
  scopes: string[];
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}

// ---------- Catalogue and decoys ----------

export type DecoyKind = "sandbox" | "emulation";
export type EntryStatus = "draft" | "verified" | "deprecated";

export interface CatalogueCve {
  cve_id: string;
  severity?: string;
  sources?: string[];
  auth_requirement?: string;
  notes?: string;
}

export interface ListenPort {
  port: number;
  protocol: string;
  service?: string;
}

export interface CatalogueEntry {
  id: string;
  product: string;
  vendor: string;
  version: string;
  decoy_kind: DecoyKind;
  status: EntryStatus;
  cves: CatalogueCve[];
  listen_ports: ListenPort[];
  sources: string[];
  risk_notes: string;
  expected_techniques?: string[];
  version_constraint?: string;
}

export type DecoyState =
  | "pending"
  | "starting"
  | "healthy"
  | "rotating"
  | "stopped"
  | "quarantined"
  | "failed"
  | "destroyed";

export interface Decoy {
  id: string;
  tenant_id: string;
  catalogue_id: string;
  decoy_kind: DecoyKind;
  label?: string | null;
  state: DecoyState;
  host_id?: string | null;
  generation: number;
  created_at: number;
  updated_at: number;
  expires_at: number;
  created_by: string;
}

export interface CreateDecoy {
  catalogue_id: string;
  label?: string;
  lifetime_seconds?: number;
  allow_draft?: boolean;
  sensor_id?: string;
}

export type JobKind =
  | "decoy.create"
  | "decoy.stop"
  | "decoy.rotate"
  | "decoy.reset"
  | "decoy.mark_compromised"
  | "decoy.destroy";

export interface JobAccepted {
  decoy: Decoy;
  job_id: string;
  job_kind: JobKind;
}

export type ReasonCode =
  | "max_lifetime"
  | "idle"
  | "reverse_shell"
  | "egress_blocked"
  | "yara_match"
  | "canary_used"
  | "honeyscore_high"
  | "health_failed"
  | "operator_manual";

export interface Reason {
  code: ReasonCode;
  text: string;
}

export type DecoyAction = "stop" | "rotate" | "reset" | "mark-compromised" | "destroy";

// ---------- Hosts and sensors (#31) ----------

export interface AgentRecord {
  id: string;
  tenant_id: string;
  role: "host" | "sensor";
  label: string | null;
  status: "pending" | "active" | "revoked";
  sandbox_allowed: boolean;
  share_opt_in: boolean | null;
  created_at: number;
  created_by: string;
  enrolled_at: number | null;
  cert_sha256: string | null;
  cert_expires_at: number | null;
  last_seen_at: number | null;
  last_ip: string | null;
  last_asn: number | null;
  network_changed_at: number | null;
  revoked_at: number | null;
  revoke_reason: Reason | null;
}

export interface AgentCreated {
  agent: AgentRecord;
  enrolment: { token: string; expires_at: number };
}

export interface AgentRevoked {
  agent: AgentRecord;
  ca_revoked: number;
  ca_failed: number;
}

export interface RegisterAgent {
  label?: string;
  sandbox_allowed?: boolean;
  enrolment_ttl_seconds?: number;
}

// ---------- Attempts (#25, #10, #27) ----------

export type AttemptState = "probe" | "exploit" | "post-exploitation";

export type StateSignal =
  | "first_contact"
  | "matcher"
  | "hook_trigger"
  | "hook_post_exploit"
  | "egress"
  | "file_write"
  | "process_exec"
  | "yara"
  | "canary";

export interface Attempt {
  attempt_id: string;
  tenant_id: string;
  decoy_id: string;
  catalogue_id: string;
  decoy_kind: DecoyKind;
  sensor_id?: string | null;
  /** Hostile. */
  src: string;
  first_seen: number;
  last_seen: number;
  state: AttemptState;
  state_history: { state: AttemptState; at: number; signal: StateSignal; event_id: string }[];
  event_ids: string[];
  payload_refs: string[];
  ioc_refs: string[];
  hook_hits: {
    hook_id: string;
    cve_id: string | null;
    stage: "trigger" | "post_exploit" | "cleanup";
    event_id: string;
    ts: number;
  }[];
  campaign_id?: string | null;
  /** Hostile values. */
  labels: Record<string, string>;
  noise?: {
    score: number;
    band: "targeted" | "mixed" | "mass";
    hits: number;
    decoy_types_touched: number;
    decoys_touched: number;
    fleet_scope: string;
    evidence: string[];
  } | null;
}

export interface AttemptList {
  items: Attempt[];
  truncated: boolean;
}

export type Channel =
  | "network"
  | "application"
  | "filesystem"
  | "process"
  | "quarantine"
  | "hook"
  | "dns"
  | "egress";

export interface TimelineEntry {
  seq: number;
  ts: number;
  t_offset_ms: number;
  channel: Channel;
  severity: "info" | "low" | "medium" | "high" | "critical";
  /** Escaped by the API; still hostile in origin. */
  summary: string;
  state_change?: { state: AttemptState; signal: StateSignal };
  event: { event_id: string; ts: number; channel: string; [key: string]: unknown };
}

export interface AttemptTimeline {
  attempt_id: string;
  decoy_id: string;
  catalogue_id: string;
  src: string;
  first_seen: number;
  last_seen: number;
  state: AttemptState;
  entries: TimelineEntry[];
  payload_refs: string[];
  ioc_refs: string[];
  pcap: {
    filter: string;
    from_ms: number;
    to_ms: number;
    host_glob: string;
    r2_prefix: string;
    output_path: string;
  };
  notes: string[];
  missing_event_ids: string[];
}

export type EvidenceSource =
  | "rule"
  | "sequence"
  | "vuln_path_hook"
  | "catalogue_prior"
  | "vendor_desc"
  | "predisclosure_backmatch"
  | "enrichment"
  | "llm"
  | "analyst"
  | "campaign_cluster"
  | "noise_score";

export interface Evidence {
  signal_id: string;
  source: EvidenceSource;
  weight: number;
  summary: string;
  ref?: string;
}

export interface Contribution {
  source: EvidenceSource;
  points: number;
  signal_ids: string[];
}

export type Feedback = "true_positive" | "false_positive" | "unsure";

export interface LinkOverride {
  feedback: Feedback;
  analyst_id: string;
  at: number;
  note: string;
}

export type LinkKind =
  | "attempt_cve"
  | "attempt_technique"
  | "attempt_actor"
  | "attempt_campaign"
  | "attempt_ioc";

export type LinkWording =
  | "we assess as"
  | "confirmed"
  | "possible association"
  | "confirmed association"
  | "possible";

export type Band = "low" | "medium" | "high";

export interface ConfidenceLink {
  kind: LinkKind;
  attempt_id: string;
  target: string;
  score: number;
  band: Band;
  wording: LinkWording;
  evidence: Evidence[];
  contributions: Contribution[];
  caps_applied: string[];
  override?: LinkOverride;
  publishable: boolean;
  ui_highlight: boolean;
  auto_state_promote: boolean;
  radar_queue: boolean;
}

/** The score block embedded in IOCs and campaigns. */
export interface ScoreSummary {
  score: number;
  band: Band;
  wording: LinkWording;
  publishable: boolean;
  evidence: Evidence[];
  caps_applied: string[];
}

// ---------- IOCs (#34) ----------

export type IocType =
  | "ip"
  | "ipv6"
  | "domain"
  | "url"
  | "http_path"
  | "http_ua"
  | "request_substring"
  | "payload_sha256"
  | "file_sha256"
  | "cmdline"
  | "dns_query"
  | "behaviour_fingerprint";

export type IocRole =
  | "source"
  | "request"
  | "payload"
  | "callback"
  | "stage2"
  | "post_exploit"
  | "behaviour";

export interface Ioc {
  ioc_id: string;
  type: IocType;
  /** Hostile and exact. Never rendered; use `display`. */
  value: string;
  /** Defanged and escaped by the API; still rendered through toPrintable. */
  display: string;
  roles: IocRole[];
  origin: "observed" | "enrichment_pivot";
  redacted: boolean;
  file_ioc_limited: boolean;
  first_seen: number;
  last_seen: number;
  sightings: number;
  attempt_ids: string[];
  campaign_ids: string[];
  decoy_ids: string[];
  catalogue_ids: string[];
  event_ids: string[];
  extracted_from: string[];
  enrichment: {
    provider: string;
    key: string;
    value: unknown;
    observed_at: number;
    shareable: boolean;
  }[];
  fingerprint?: { version: 2; steps: string[] };
  confidence: ScoreSummary;
}

export interface IocList {
  items: Ioc[];
  truncated: boolean;
}

export interface AttemptIocs {
  attempt_id: string;
  file_ioc_limited: boolean;
  notes: string[];
  items: Ioc[];
  truncated: boolean;
}

// ---------- Campaigns (#33) ----------

export type CampaignStatus = "emerging" | "active" | "closed";
export type CampaignActionKind = "label" | "status" | "merge" | "split" | "feedback";

export interface CampaignJoin {
  signal_id: string;
  feature: string;
  families: ("infrastructure" | "ttp" | "targeting" | "payload")[];
  strength: "strong" | "medium" | "weak";
  weight: 100 | 70 | 40;
  /** Defanged and escaped. Never parse. */
  display: string;
  with_attempt_id: string;
  ioc_id?: string;
}

export interface CampaignMember {
  attempt_id: string;
  decoy_id: string;
  catalogue_id: string;
  sensor_id: string | null;
  /** Hostile. */
  src: string;
  first_seen: number;
  last_seen: number;
  state: AttemptState;
  noise_score: number | null;
  joined_by: CampaignJoin[];
  added_by?: { action_id: string; kind: CampaignActionKind; analyst_id: string; at: number };
  carried_over?: boolean;
}

export interface CampaignBridge {
  campaign_id: string;
  merged_campaign_id: string | null;
  attempt_id: string;
  with_attempt_id: string;
  signal_id: string;
  feature: string;
  attempt_side: number;
  with_side: number;
  small_halves: boolean;
  recorded_at: number;
}

export interface PossibleLink {
  other_campaign_ids: string[];
  attempt_ids: string[];
  /** Hostile. */
  src: string;
  signal_ids: string[];
}

export interface ActorLink {
  /** A named public cluster (#29). */
  label: string;
  wording: "possible association" | "confirmed association";
  confidence_ref: string;
  report_urls: string[];
}

export interface Counted {
  count: number;
  /** Defanged and escaped. Never parse. */
  values: string[];
}

export interface Campaign {
  campaign_id: string;
  tenant_id: string;
  tenant_scope: "tenant";
  /** Escaped by the API. */
  title: string;
  status: CampaignStatus;
  first_seen: number;
  last_seen: number;
  seed: { attempt_id: string; features: string[] };
  attempt_ids: string[];
  decoy_ids: string[];
  sensor_ids: string[];
  catalogue_ids: string[];
  members: CampaignMember[];
  feature_summary: {
    infrastructure: {
      src_ips: Counted;
      asns: number[];
      stage2_urls: Counted;
      callback_domains: Counted;
      callback_ips: Counted;
    };
    ttp: { techniques: string[]; behaviour_fingerprints: Counted; cmdlines: Counted };
    targeting: {
      pattern: "mass" | "mixed" | "selective";
      attempts: number;
      sources: number;
      evidence: string[];
      [key: string]: unknown;
    };
    payload: { [key: string]: unknown };
  };
  shared_ioc_ids: string[];
  confidence_ref: string;
  confidence: ScoreSummary;
  suggested_actor_links: ActorLink[];
  analyst: {
    title: string | null;
    status: CampaignStatus | null;
    feedback: LinkOverride | null;
    merged_from: string[];
    split_from: string | null;
    action_ids: string[];
  };
  possible_links: PossibleLink[];
  bridges: CampaignBridge[];
  notes: string[];
}

export interface CampaignStub {
  campaign_id: string;
  tenant_id: string;
  stub: true;
  first_seen: number;
  last_seen: number;
  attempt_count: number;
  merged_into: string | null;
  notes: string[];
}

export interface CampaignList {
  items: Campaign[];
  truncated: boolean;
  notes: string[];
}

export interface CampaignAttempts {
  campaign_id: string;
  items: Attempt[];
  truncated: boolean;
}

export interface CampaignEvidence {
  campaign_id: string;
  confidence: ConfidenceLink;
  members: ConfidenceLink[];
  bridges: CampaignBridge[];
  possible_links: PossibleLink[];
  truncated: boolean;
}

export interface CampaignAction {
  action_id: string;
  kind: CampaignActionKind;
  campaign_id: string;
  anchor_attempt_ids: string[];
  title?: string;
  status?: CampaignStatus;
  merge?: { campaign_id: string; anchor_attempt_ids: string[] }[];
  attempt_ids?: string[];
  feedback?: Feedback;
  note: string;
  analyst_id: string;
  at: number;
}

export interface CampaignActionRequest {
  action: CampaignActionKind;
  title?: string;
  status?: CampaignStatus | null;
  campaign_ids?: string[];
  attempt_ids?: string[];
  feedback?: Feedback;
  note: string;
}

// ---------- Audit ----------

export interface AuditRecord {
  id: string;
  ts: number;
  tenant_id: string;
  actor_id: string;
  actor_kind: "human" | "mcp" | "host" | "sensor";
  action: string;
  target?: string | null;
  reason_code?: string | null;
  reason_text?: string | null;
  job_id?: string | null;
  idempotency_key?: string | null;
  outcome: "accepted" | "denied" | "failed";
  detail?: unknown;
}

export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

// ---------- Review queue (#35, planned) ----------
//
// TODO(#35): `/v0/review-queue` is `planned` in api/openapi.yaml and no
// shape is published yet. These types are the console's proposal, written
// from the #14 and #35 issue text and the `review_queue_item` alert
// (testdata/alerts/review-queue-item.json). Replace them with the shapes
// #35 ships; the console shows "not served yet" until the route answers.

export type ReviewKind =
  | "predisclosure_candidate"
  | "low_confidence_high_impact"
  | "campaign_suggestion";

export type ReviewStatus = "open" | "confirmed" | "rejected" | "snoozed";
export type ReviewDecision = "confirm" | "reject" | "snooze";

export interface ReviewItem {
  item_id: string;
  kind: ReviewKind;
  status: ReviewStatus;
  created_at: number;
  updated_at: number;
  snoozed_until: number | null;
  attempt_id: string | null;
  campaign_id: string | null;
  catalogue_id: string | null;
  /** Escaped by the API; rendered through toPrintable. */
  summary: string;
  /** The link the item asks an analyst to judge, when there is one. */
  link: ConfidenceLink | null;
  decision: { action: ReviewDecision; analyst_id: string; at: number; note: string } | null;
}

export interface ReviewActionRequest {
  action: ReviewDecision;
  note: string;
  /** Snooze only. Unix ms. */
  snooze_until?: number;
}

// ---------- Quarantine (#9 list, #14 download; planned) ----------
//
// TODO(#9): `GET /v0/quarantine` is planned. Items follow
// schemas/quarantine-meta.schema.json. TODO(#14 follow-up): the one-time
// download (`POST /v0/quarantine/{sha256}:download`) is planned; the body and
// response below are the console's proposal.

export interface QuarantineItem {
  sha256: string;
  sha1?: string;
  md5?: string;
  size: number;
  mime_guess?: string;
  first_seen: number;
  last_seen?: number;
  decoy_id: string;
  catalogue_id: string;
  attempt_id?: string;
  capture_channel: "filesystem" | "application" | "network" | "hook";
  /** Hostile. */
  guest_path?: string;
  /** Hostile. */
  src?: string;
  payload_ref: string;
  executed: false;
  yara_matches?: string[];
}

export interface QuarantineDownloadRequest {
  /** The full SHA-256, typed back by the analyst as the second confirmation. */
  confirm_sha256: string;
  note: string;
}

export interface QuarantineDownloadGrant {
  url: string;
  expires_at: number;
}

// ---------- Exports (#13) ----------

export type Tlp = "clear" | "green" | "amber" | "amber+strict" | "red";
