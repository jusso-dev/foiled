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
  | "review:publish"
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
  | "actor_ttp_overlap"
  | "actor_indicator_overlap"
  | "actor_targeting"
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

/** `Campaign.suggested_actor_links` (#29). */
export interface ActorLink {
  link_id: string;
  actor_id: string;
  /** A public nexus, cluster or group label (#29). */
  label: string;
  wording: "possible association" | "confirmed association";
  score: number;
  band: Band;
  status: "pending" | "confirmed";
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

// ---------- Review queue, write-ups and radar (#35) ----------
//
// schemas/review-item.schema.json, write-up.schema.json and
// radar-feed.schema.json (docs/review-queue.md, research-writeups.md, radar.md).

export type ReviewKind =
  | "cve_link"
  | "predisclosure_candidate"
  | "technique_link"
  | "ioc_publication"
  | "campaign_label"
  | "campaign_merge"
  | "false_positive_feedback"
  | "actor_association"
  | "write_up";

/**
 * `needs_attention`: a decision did not finish or its rollback failed. It is
 * listed first and can be decided again after a minute.
 */
export type ReviewStatus =
  | "open"
  | "claimed"
  | "snoozed"
  | "approved"
  | "rejected"
  | "needs_attention";
export type ReviewAction =
  | "claim"
  | "assign"
  | "release"
  | "approve"
  | "reject"
  | "snooze"
  | "promote";

export interface WriteUpChecklist {
  tenant_data_removed: boolean;
  wording_checked: boolean;
  no_exploit_code: boolean;
  payloads_redacted: boolean;
  sources_linked: boolean;
  delay_rules_checked: boolean;
}

export interface ReviewItem {
  item_id: string;
  tenant_id: string;
  kind: ReviewKind;
  subject: {
    attempt_id?: string;
    /** CVE id, technique id or actor label. */
    target?: string;
    ioc_id?: string;
    campaign_id?: string;
    /** campaign_merge: the campaign to fold into campaign_id. */
    other_campaign_id?: string;
    writeup_id?: string;
    /** actor_association: a confirmed link that needs another look. */
    revision?: string;
    submitted_at?: number;
  };
  /** Escaped one-line summary. */
  title: string;
  score: number;
  band: Band;
  wording: string;
  status: ReviewStatus;
  assignee: string | null;
  claimed_at: number | null;
  snoozed_until: number | null;
  decided_by: string | null;
  decided_at: number | null;
  note: string;
  created_at: number;
  age_ms: number;
  sla_hours: number;
  sla_due_at: number;
  sla_breached: boolean;
  priority: number;
  version: number;
}

export interface ReviewList {
  items: ReviewItem[];
  total: number;
  truncated: boolean;
  notes: string[];
}

export interface ReviewActionRequest {
  action: ReviewAction;
  assignee?: string;
  /** Snooze only. Unix ms, at most 30 days away. */
  until?: number;
  /** Required for reject. */
  note?: string;
  expected_version?: number;
  /** Approve on campaign_label: the campaign title. */
  label?: string;
  /** Approve on write_up. */
  checklist?: WriteUpChecklist;
}

export interface ReviewActionResult {
  item: ReviewItem;
  effect: string | null;
  writeup_id: string | null;
}

export type WriteUpStatus = "draft" | "review" | "approved" | "published" | "withdrawn";

export interface LintFinding {
  rule: string;
  severity: "error" | "warning";
  location: string;
  message: string;
}

export interface WriteUp {
  writeup_id: string;
  tenant_id: string;
  slug: string;
  title: string;
  summary: string;
  /** Markdown subset. Never rendered as HTML by the console: shown as text. */
  body_md: string;
  status: WriteUpStatus;
  tlp: Tlp;
  embargo_until: number | null;
  cve_ids: string[];
  technique_ids: string[];
  campaign_ids: string[];
  ioc_ids: string[];
  attempt_ids: string[];
  first_seen: number | null;
  redacted_payload: string | null;
  source_item_id: string | null;
  author_id: string;
  reviewer_id: string | null;
  checklist: WriteUpChecklist | null;
  version: number;
  created_at: number;
  updated_at: number;
  submitted_at: number | null;
  approved_at: number | null;
  published_at: number | null;
  withdrawn_at: number | null;
  lint?: LintFinding[];
}

export interface WriteUpFields {
  slug?: string;
  title?: string;
  summary?: string;
  body_md?: string;
  tlp?: Tlp;
  embargo_until?: number | null;
  cve_ids?: string[];
  technique_ids?: string[];
  campaign_ids?: string[];
  ioc_ids?: string[];
  attempt_ids?: string[];
  first_seen?: number | null;
  redacted_payload?: string | null;
  expected_version?: number;
}

export interface WriteUpTransition {
  to: WriteUpStatus;
  expected_version?: number;
  note?: string;
  checklist?: WriteUpChecklist;
}

export interface WriteUpVersion {
  writeup: WriteUp;
  action: string;
  actor_id: string;
  at: number;
}

export type RadarDimension = "cve" | "technique" | "campaign" | "product";

export interface RadarSeries {
  dimension: RadarDimension;
  key: string;
  label: string;
  wording: "we assess as" | "possible" | "observed";
  total_attempts: number;
  total_sources: number;
  best_band: Band;
  first_day: number;
  last_day: number;
  days: { day: number; attempts: number; publishable_attempts: number; sources: number }[];
  trend: { direction: "up" | "down" | "flat"; pct: number };
}

export interface RadarCard {
  card_id: string;
  kind: "new_cve_assessment" | "predisclosure_spike" | "campaign_emergence" | "spike";
  dimension: RadarDimension;
  key: string;
  day: number;
  attempts: number;
  sources: number;
  headline: string;
}

export interface RadarFeed {
  /** Trusted side only: there is no public radar. */
  audience: "fleet" | "tenant";
  generated_at: number;
  since: number;
  until: number;
  policy: {
    min_sources: number;
    min_sensors: number;
    min_edge_tenants: number;
    min_confidence: Band;
  };
  series: RadarSeries[];
  cards: RadarCard[];
  /** Buckets, or filtered slices of buckets, held back by the thresholds. */
  suppressed_buckets: number;
  notes: string[];
}

// ---------- Actor possible-associations (#29) ----------
//
// `/v0/actor-links` (docs/actor-attribution.md, schemas/actor-link.schema.json).

export interface ActorLinkRecord {
  link_id: string;
  tenant_id: string;
  subject_kind: "campaign" | "attempt";
  subject_id: string;
  attempt_ids: string[];
  /** Confirmed links: the attempts the confirmation covers. Only these export as confirmed. */
  confirmed_attempt_ids?: string[];
  /** Confirmed links: attempts that joined since. Not covered; the link is back in review. */
  new_since_confirmation?: string[];
  actor_id: string;
  label: string;
  label_kind: "nexus" | "cluster" | "named_group";
  status: "pending" | "confirmed" | "rejected";
  wording: "possible association" | "confirmed association";
  /** The only sentence the API allows clients to show for this link. */
  statement: string;
  score: number;
  band: Band;
  publishable: boolean;
  review_queue: boolean;
  matched: {
    techniques: { id: string; profiles_using: number; rarity: number }[];
    indicators: {
      type: "ip" | "cidr" | "domain" | "url" | "sha256" | "asn";
      /** Defanged and escaped. */
      display: string;
      match: "exact" | "subdomain" | "in_range";
      ioc_id?: string;
      weight: number;
      stale: boolean;
      source_url: string;
    }[];
    targeting: string[];
  };
  not_counted: string[];
  sources: {
    kind: "attack_group" | "vendor_report" | "government_advisory" | "misp_galaxy";
    publisher: string;
    title: string;
    url: string;
    published: string;
    retrieved?: string;
    sha256?: string;
    licence: string;
    licence_url?: string;
  }[];
  attack_version?: string;
  example: boolean;
  confidence: ConfidenceLink;
}

export type ActorDecision = "confirm" | "reject" | "reopen";

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
