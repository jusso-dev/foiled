/**
 * API responses for console tests. Where the repository has golden output
 * from the Rust code (testdata/), the tests use it unchanged, so the console
 * is tested against the shapes the API really produces.
 */

import actorLinkJson from "../../../testdata/actors/expected/fleet-wave-00.json";
import hostPending from "../../../testdata/agent/registry/host-pending.json";
import sensorActive from "../../../testdata/agent/registry/sensor-active.json";
import sensorRevoked from "../../../testdata/agent/registry/sensor-revoked.json";
import attemptProbe from "../../../testdata/attempts/expected/demo-fleet-0.json";
import attemptRedis from "../../../testdata/attempts/expected/demo-fleet-1.json";
import attemptPost from "../../../testdata/attempts/expected/demo-fleet-2.json";
import timelinePost from "../../../testdata/attempts/timeline/demo-fleet-2.json";
import campaignWave from "../../../testdata/campaigns/expected/fleet-wave-00.json";
import hookLink from "../../../testdata/confidence-links/hook-and-sequence-high.json";
import llmLink from "../../../testdata/confidence-links/llm-only-capped.json";
import iocIp from "../../../testdata/iocs/expected/file-drop-00.json";
import radarJson from "../../../testdata/radar/expected/tenant-edge-d.json";
import reviewCve from "../../../testdata/review/expected/fleet-wave-00.json";
import reviewIocPub from "../../../testdata/review/expected/fleet-wave-05.json";
import writeUpJson from "../../../testdata/write-ups/examples/demo-app-upload-traversal.json";
import type {
  ActorLinkRecord,
  AgentRecord,
  Attempt,
  AttemptTimeline,
  Campaign,
  CatalogueEntry,
  ConfidenceLink,
  Decoy,
  Ioc,
  QuarantineItem,
  RadarFeed,
  ReviewItem,
  WriteUp,
} from "../lib/api-types";

const as = <T>(v: unknown) => structuredClone(v) as T;

export const attempts = {
  probe: as<Attempt>(attemptProbe),
  redis: as<Attempt>(attemptRedis),
  post: as<Attempt>(attemptPost),
};
export const timeline = as<AttemptTimeline>(timelinePost);
export const campaign = as<Campaign>(campaignWave);
export const ioc = as<Ioc>(iocIp);
export const agents = {
  host: as<AgentRecord>(hostPending),
  sensor: as<AgentRecord>(sensorActive),
  revoked: { ...as<AgentRecord>(sensorRevoked), id: "sen-0002" },
};

/** The hook-and-sequence link, retargeted at the post-exploitation attempt. */
export const cveLink: ConfidenceLink = {
  ...as<ConfidenceLink>(hookLink),
  attempt_id: attempts.post.attempt_id,
};

/** An LLM-only proposal: capped, low, not publishable. */
export const llmCveLink: ConfidenceLink = {
  ...as<ConfidenceLink>(llmLink),
  attempt_id: attempts.post.attempt_id,
  caps_applied: ["LLM-only evidence capped below high"],
};

export const actorLink: ConfidenceLink = {
  kind: "attempt_actor",
  attempt_id: attempts.post.attempt_id,
  target: "Example Cluster 7",
  score: 45,
  band: "medium",
  wording: "possible association",
  evidence: [
    {
      signal_id: "enrich:report-1",
      source: "enrichment",
      weight: 60,
      summary: "public report names this infrastructure",
    },
  ],
  contributions: [{ source: "enrichment", points: 6, signal_ids: ["enrich:report-1"] }],
  caps_applied: [],
  publishable: false,
  ui_highlight: false,
  auto_state_promote: false,
  radar_queue: true,
};

export const catalogue: Record<string, CatalogueEntry> = {
  demo: {
    id: "foiled/demo-app/1.0.0",
    product: "Foiled demo app",
    vendor: "Foiled project",
    version: "1.0.0",
    decoy_kind: "sandbox",
    status: "verified",
    cves: [
      {
        cve_id: "FOILED-DEMO-0001",
        severity: "critical",
        sources: ["synthetic"],
        auth_requirement: "unauth",
      },
    ],
    listen_ports: [{ port: 8080, protocol: "tcp", service: "http" }],
    sources: ["https://github.com/jusso-dev/foiled"],
    risk_notes: "Deliberately vulnerable synthetic app for the MVP walkthrough. Not wormable.",
    expected_techniques: ["T1190", "T1505.003"],
  },
  redis: {
    id: "emulator/redis/7.0",
    product: "Redis",
    vendor: "Redis",
    version: "7.0.11",
    decoy_kind: "emulation",
    status: "draft",
    cves: [{ cve_id: "CVE-2099-0001", severity: "high", sources: ["synthetic"] }],
    listen_ports: [{ port: 6379, protocol: "tcp", service: "redis" }],
    sources: [],
    risk_notes: "The emulator answers a small command subset and never runs attacker Lua.",
    expected_techniques: ["T1190"],
  },
  ssl: {
    id: "emulator/ssl-vpn/portal-generic",
    product: "ExampleVPN portal",
    vendor: "Example",
    version: "generic",
    decoy_kind: "emulation",
    status: "verified",
    cves: [],
    listen_ports: [{ port: 443, protocol: "tcp" }],
    sources: [],
    risk_notes: "Login page emulation only.",
  },
};

export function decoy(over: Partial<Decoy> = {}): Decoy {
  return {
    id: "dcy-0001",
    tenant_id: "t1",
    catalogue_id: "emulator/ssl-vpn/portal-generic",
    decoy_kind: "emulation",
    label: "edge vpn",
    state: "pending",
    host_id: null,
    generation: 1,
    created_at: 1792285000000,
    updated_at: 1792285000000,
    expires_at: 1792371400000,
    created_by: "tok1",
    ...over,
  };
}

/** Review queue, write-up, radar (#35) and actor (#29) shapes: golden output from testdata/. */
export const reviewItem = as<ReviewItem>(reviewCve);
export const reviewIoc = as<ReviewItem>(reviewIocPub);
export const writeUp = as<WriteUp>(writeUpJson);
export const radarFeed = as<RadarFeed>(radarJson);
export const actorLinkRecord = as<ActorLinkRecord>(actorLinkJson);

export const quarantined: QuarantineItem = {
  sha256: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  size: 4096,
  mime_guess: "application/x-sh",
  first_seen: 1792285384020,
  decoy_id: "dcy-demo-1",
  catalogue_id: "foiled/demo-app/1.0.0",
  capture_channel: "filesystem",
  guest_path: "/tmp/x.sh",
  payload_ref: "r2://foiled-evidence/t1/dcy-demo-1/_/quarantine/5e88",
  executed: false,
};

/** Attacker text that tries markup, a bidi override and a control character. */
export const HOSTILE = "<img src=x onerror=alert(1)>‮gnp.exe\u0007";
