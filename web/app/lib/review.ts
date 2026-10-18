/**
 * Review queue wording (#35). Each item kind is worded with the same rules
 * as the link it stands for: "we assess as" for CVEs and techniques,
 * "possible association" for actors, "possible" for campaigns.
 */

import type { Band, LinkWording, ReviewItem, ReviewKind, WriteUpChecklist } from "./api-types";
import { campaignSentence, linkSentence } from "./links";

export const REVIEW_KIND_LABEL: Record<ReviewKind, string> = {
  cve_link: "CVE link",
  predisclosure_candidate: "Pre-disclosure candidate",
  technique_link: "Technique link",
  ioc_publication: "IOC publication",
  campaign_label: "Campaign label",
  actor_association: "Actor possible association",
  write_up: "Write-up in review",
};

const KNOWN: ReadonlySet<string> = new Set([
  "we assess as",
  "confirmed",
  "possible association",
  "confirmed association",
  "possible",
]);

/** The item's wording as a link wording; anything unexpected is treated as unconfirmed. */
export function itemWording(item: Pick<ReviewItem, "wording" | "kind">): LinkWording {
  if (KNOWN.has(item.wording)) return item.wording as LinkWording;
  return item.kind === "actor_association"
    ? "possible association"
    : item.kind === "campaign_label"
      ? "possible"
      : "we assess as";
}

/** One sentence for an item, or null when it has no score to word (write-ups). */
export function reviewSentence(
  item: Pick<ReviewItem, "kind" | "subject" | "score" | "band" | "wording">,
): string | null {
  const wording = itemWording(item);
  const target = item.subject.target ?? item.subject.ioc_id ?? item.subject.campaign_id ?? "";
  const base = { target, score: item.score, band: item.band as Band, wording };
  switch (item.kind) {
    case "cve_link":
    case "predisclosure_candidate":
      return linkSentence({ ...base, kind: "attempt_cve" });
    case "technique_link":
      return linkSentence({ ...base, kind: "attempt_technique" });
    case "actor_association":
      return linkSentence({ ...base, kind: "attempt_actor" });
    case "ioc_publication":
      return linkSentence({ ...base, kind: "attempt_ioc" });
    case "campaign_label":
      return campaignSentence(item.score, wording);
    case "write_up":
      return null;
  }
}

export const CHECKLIST: readonly { key: string; label: string }[] = [
  { key: "tenant_data_removed", label: "Tenant data removed" },
  { key: "wording_checked", label: 'Wording checked ("we assess as", "possible association")' },
  { key: "no_exploit_code", label: "No exploit code or runnable commands" },
  { key: "payloads_redacted", label: "Payloads redacted" },
  { key: "sources_linked", label: "Sources linked" },
  { key: "delay_rules_checked", label: "Delay and embargo rules checked" },
];

/** The checklist from a form: each item is true only when its box was ticked. */
export function checklistFrom(form: FormData): WriteUpChecklist {
  const on = (k: string) => form.get(`check_${k}`) === "yes";
  return {
    tenant_data_removed: on("tenant_data_removed"),
    wording_checked: on("wording_checked"),
    no_exploit_code: on("no_exploit_code"),
    payloads_redacted: on("payloads_redacted"),
    sources_linked: on("sources_linked"),
    delay_rules_checked: on("delay_rules_checked"),
  };
}

export function checklistComplete(c: WriteUpChecklist): boolean {
  return Object.values(c).every(Boolean);
}
