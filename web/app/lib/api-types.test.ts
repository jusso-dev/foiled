/**
 * Drift check between lib/api-types.ts and the JSON Schemas the API is
 * tested against. Each `Record<keyof T, true>` below must list every key of
 * the TypeScript type (the compiler enforces that); the test then checks the
 * list against the schema both ways.
 */

import { describe, expect, it } from "vitest";
import actorLinkSchema from "../../../schemas/actor-link.schema.json";
import agentSchema from "../../../schemas/agent/agent-record.schema.json";
import attemptSchema from "../../../schemas/attempt.schema.json";
import timelineSchema from "../../../schemas/attempt-timeline.schema.json";
import campaignSchema from "../../../schemas/campaign.schema.json";
import actionSchema from "../../../schemas/campaign-action.schema.json";
import linkSchema from "../../../schemas/confidence-link.schema.json";
import iocSchema from "../../../schemas/ioc.schema.json";
import quarantineSchema from "../../../schemas/quarantine-meta.schema.json";
import radarSchema from "../../../schemas/radar-feed.schema.json";
import reviewSchema from "../../../schemas/review-item.schema.json";
import writeUpSchema from "../../../schemas/write-up.schema.json";
import type {
  ActorLinkRecord,
  AgentRecord,
  Attempt,
  AttemptTimeline,
  Campaign,
  CampaignAction,
  ConfidenceLink,
  Ioc,
  QuarantineItem,
  RadarFeed,
  ReviewItem,
  WriteUp,
} from "./api-types";

type Keys<T> = Record<keyof T, true>;

const attempt: Keys<Attempt> = {
  attempt_id: true,
  tenant_id: true,
  decoy_id: true,
  catalogue_id: true,
  decoy_kind: true,
  sensor_id: true,
  src: true,
  first_seen: true,
  last_seen: true,
  state: true,
  state_history: true,
  event_ids: true,
  payload_refs: true,
  ioc_refs: true,
  hook_hits: true,
  campaign_id: true,
  labels: true,
  noise: true,
};

const timeline: Keys<AttemptTimeline> = {
  attempt_id: true,
  decoy_id: true,
  catalogue_id: true,
  src: true,
  first_seen: true,
  last_seen: true,
  state: true,
  entries: true,
  payload_refs: true,
  ioc_refs: true,
  pcap: true,
  notes: true,
  missing_event_ids: true,
};

const link: Keys<ConfidenceLink> = {
  kind: true,
  attempt_id: true,
  target: true,
  score: true,
  band: true,
  wording: true,
  evidence: true,
  contributions: true,
  caps_applied: true,
  override: true,
  publishable: true,
  ui_highlight: true,
  auto_state_promote: true,
  radar_queue: true,
};

const ioc: Keys<Ioc> = {
  ioc_id: true,
  type: true,
  value: true,
  display: true,
  roles: true,
  origin: true,
  redacted: true,
  file_ioc_limited: true,
  first_seen: true,
  last_seen: true,
  sightings: true,
  attempt_ids: true,
  campaign_ids: true,
  decoy_ids: true,
  catalogue_ids: true,
  event_ids: true,
  extracted_from: true,
  enrichment: true,
  fingerprint: true,
  confidence: true,
};

const campaign: Keys<Campaign> = {
  campaign_id: true,
  tenant_id: true,
  tenant_scope: true,
  title: true,
  status: true,
  first_seen: true,
  last_seen: true,
  seed: true,
  attempt_ids: true,
  decoy_ids: true,
  sensor_ids: true,
  catalogue_ids: true,
  members: true,
  feature_summary: true,
  shared_ioc_ids: true,
  confidence_ref: true,
  confidence: true,
  suggested_actor_links: true,
  analyst: true,
  possible_links: true,
  bridges: true,
  notes: true,
};

const action: Keys<CampaignAction> = {
  action_id: true,
  kind: true,
  campaign_id: true,
  anchor_attempt_ids: true,
  title: true,
  status: true,
  merge: true,
  attempt_ids: true,
  feedback: true,
  note: true,
  analyst_id: true,
  at: true,
};

const agent: Keys<AgentRecord> = {
  id: true,
  tenant_id: true,
  role: true,
  label: true,
  status: true,
  sandbox_allowed: true,
  share_opt_in: true,
  created_at: true,
  created_by: true,
  enrolled_at: true,
  cert_sha256: true,
  cert_expires_at: true,
  last_seen_at: true,
  last_ip: true,
  last_asn: true,
  network_changed_at: true,
  revoked_at: true,
  revoke_reason: true,
};

const quarantine: Keys<QuarantineItem> = {
  sha256: true,
  sha1: true,
  md5: true,
  size: true,
  mime_guess: true,
  first_seen: true,
  last_seen: true,
  decoy_id: true,
  catalogue_id: true,
  attempt_id: true,
  capture_channel: true,
  guest_path: true,
  src: true,
  payload_ref: true,
  executed: true,
  yara_matches: true,
};

const review: Keys<ReviewItem> = {
  item_id: true,
  tenant_id: true,
  kind: true,
  subject: true,
  title: true,
  score: true,
  band: true,
  wording: true,
  status: true,
  assignee: true,
  claimed_at: true,
  snoozed_until: true,
  decided_by: true,
  decided_at: true,
  note: true,
  created_at: true,
  age_ms: true,
  sla_hours: true,
  sla_due_at: true,
  sla_breached: true,
  priority: true,
  version: true,
};

const writeUp: Keys<WriteUp> = {
  writeup_id: true,
  tenant_id: true,
  slug: true,
  title: true,
  summary: true,
  body_md: true,
  status: true,
  tlp: true,
  embargo_until: true,
  cve_ids: true,
  technique_ids: true,
  campaign_ids: true,
  ioc_ids: true,
  attempt_ids: true,
  first_seen: true,
  redacted_payload: true,
  source_item_id: true,
  author_id: true,
  reviewer_id: true,
  checklist: true,
  version: true,
  created_at: true,
  updated_at: true,
  submitted_at: true,
  approved_at: true,
  published_at: true,
  withdrawn_at: true,
  lint: true,
};

const radar: Keys<RadarFeed> = {
  audience: true,
  generated_at: true,
  since: true,
  until: true,
  policy: true,
  series: true,
  cards: true,
  suppressed_buckets: true,
  notes: true,
};

const actorLink: Keys<ActorLinkRecord> = {
  link_id: true,
  tenant_id: true,
  subject_kind: true,
  subject_id: true,
  attempt_ids: true,
  actor_id: true,
  label: true,
  label_kind: true,
  status: true,
  wording: true,
  statement: true,
  score: true,
  band: true,
  publishable: true,
  review_queue: true,
  matched: true,
  not_counted: true,
  confirmed_attempt_ids: true,
  restricted: true,
  new_since_confirmation: true,
  sources: true,
  attack_version: true,
  example: true,
  confidence: true,
};

const CASES: [string, Record<string, true>, { required: string[]; properties: object }][] = [
  ["attempt", attempt, attemptSchema],
  ["attempt-timeline", timeline, timelineSchema],
  ["confidence-link", link, linkSchema],
  ["ioc", ioc, iocSchema],
  ["campaign", campaign, campaignSchema],
  ["campaign-action", action, actionSchema],
  ["agent-record", agent, agentSchema],
  ["quarantine-meta", quarantine, quarantineSchema],
  ["review-item", review, reviewSchema],
  ["write-up", writeUp, writeUpSchema],
  ["radar-feed", radar, radarSchema],
  ["actor-link", actorLink, actorLinkSchema],
];

describe("api-types match the JSON Schemas", () => {
  for (const [name, keys, schema] of CASES) {
    it(`${name}: same properties, required ones present`, () => {
      expect(Object.keys(keys).sort(), name).toEqual(Object.keys(schema.properties).sort());
      for (const r of schema.required) expect(keys, `${name}.${r}`).toHaveProperty(r);
    });
  }
});
