/**
 * Plain-words explanations of confidence links (#27) for the console:
 * which chip level a link shows, the sentence it is worded with, and the
 * ledger of contributions that produced its score. Wording follows
 * docs/confidence.md and docs/ui/voice.md: "we assess as" until an analyst
 * confirms, "possible association" for actors, "possible" for campaigns.
 */

import type {
  Band,
  ConfidenceLink,
  Evidence,
  EvidenceSource,
  LinkKind,
  LinkWording,
} from "./api-types";
import type { Confidence, ConfidenceLevel } from "./confidence";
import { clampScore } from "./confidence";
import { toPrintable } from "./printable";

const CONFIRMED: ReadonlySet<LinkWording> = new Set(["confirmed", "confirmed association"]);

/** Chip level: only an analyst confirmation is Confirmed; unconfirmed `high` is Probable. */
export function levelFor(wording: LinkWording, band: Band): ConfidenceLevel {
  if (CONFIRMED.has(wording)) return "confirmed";
  return band === "high" ? "probable" : "assessed";
}

export function confidenceOf(c: { score: number; band: Band; wording: LinkWording }): Confidence {
  return { level: levelFor(c.wording, c.band), score: clampScore(c.score) };
}

export const KIND_LABEL: Record<LinkKind, string> = {
  attempt_cve: "CVE",
  attempt_technique: "ATT&CK technique",
  attempt_actor: "Actor",
  attempt_campaign: "Campaign",
  attempt_ioc: "Indicator",
};

/**
 * The full sentence for a link. `target` may be attacker-influenced (actor
 * labels come from public reports, campaign ids are ours), so it is made
 * printable here.
 */
export function linkSentence(
  link: Pick<ConfidenceLink, "kind" | "target" | "score" | "wording" | "band">,
): string {
  const t = toPrintable(link.target);
  const s = clampScore(link.score);
  const confirmed = CONFIRMED.has(link.wording);
  const tail = confirmed ? `Score ${s} of 100.` : `Score ${s} of 100, not confirmed by an analyst.`;
  switch (link.kind) {
    case "attempt_cve":
      return confirmed
        ? `Confirmed by an analyst as an attempt against ${t}. ${tail}`
        : `We assess as an attempt against ${t}. ${tail}`;
    case "attempt_technique":
      return confirmed
        ? `Confirmed by an analyst as technique ${t}. ${tail}`
        : `We assess as technique ${t}. ${tail}`;
    case "attempt_actor":
      // "confirmed association" needs both a confirmation and a high score (docs/confidence.md).
      return link.wording === "confirmed association"
        ? `Confirmed association with ${t}. ${tail}`
        : `Possible association with ${t}. ${tail}`;
    case "attempt_campaign":
      return confirmed
        ? `Confirmed by an analyst as part of campaign ${t}. ${tail}`
        : `Possible part of campaign ${t}. ${tail}`;
    case "attempt_ioc":
      return confirmed
        ? `Confirmed by an analyst as indicator ${t}. ${tail}`
        : `We assess as indicator ${t}. ${tail}`;
  }
}

/** Campaign-level sentence (`possible` or `confirmed`). */
export function campaignSentence(score: number, wording: LinkWording): string {
  const s = clampScore(score);
  return wording === "confirmed"
    ? `Confirmed by an analyst as one campaign. Score ${s} of 100.`
    : `Possible campaign: these attempts may share an operator. Score ${s} of 100, not confirmed by an analyst.`;
}

export const SOURCE_LABEL: Record<EvidenceSource, string> = {
  actor_ttp_overlap: "Shared techniques with public reporting",
  actor_indicator_overlap: "Shared indicators with public reporting",
  actor_targeting: "Similar targeting in public reporting",
  rule: "Signature rule",
  sequence: "Request sequence",
  vuln_path_hook: "Vulnerable-path hook",
  catalogue_prior: "Catalogue prior",
  vendor_desc: "Advisory description",
  predisclosure_backmatch: "Pre-disclosure back-match",
  enrichment: "Enrichment",
  llm: "LLM proposal",
  analyst: "Analyst",
  campaign_cluster: "Campaign clustering",
  noise_score: "Noise score",
};

export interface LedgerRow {
  id: string;
  signal: string;
  source: string;
  points: number;
}

/**
 * One ledger row per contribution, as recorded by the API (the console never
 * recomputes a score). The signal column lists the evidence summaries the
 * contribution counted.
 */
export function ledger(link: Pick<ConfidenceLink, "contributions" | "evidence">): LedgerRow[] {
  const bySignal = new Map<string, Evidence>(link.evidence.map((e) => [e.signal_id, e]));
  return link.contributions.map((c, i) => ({
    id: `${c.source}-${i}`,
    signal:
      c.signal_ids
        .map((id) => bySignal.get(id)?.summary ?? id)
        .map(toPrintable)
        .join("; ") || "(no signal ids)",
    source: SOURCE_LABEL[c.source] ?? c.source,
    points: c.points,
  }));
}

/** Links the analyst may override. `attempt_ioc` is scored once per IOC, not per attempt. */
export function overridable(kind: LinkKind): kind is Exclude<LinkKind, "attempt_ioc"> {
  return kind !== "attempt_ioc";
}

/** Order links for display: CVEs, techniques, campaigns, actors; strongest first. */
export function sortLinks(links: readonly ConfidenceLink[]): ConfidenceLink[] {
  const order: Record<LinkKind, number> = {
    attempt_cve: 0,
    attempt_technique: 1,
    attempt_campaign: 2,
    attempt_actor: 3,
    attempt_ioc: 4,
  };
  return [...links].sort((a, b) => order[a.kind] - order[b.kind] || b.score - a.score);
}
