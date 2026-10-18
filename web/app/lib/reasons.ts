import type { ReasonCode } from "./api-types";

/** Reason codes for destructive actions, as in docs/rotation.md, with plain labels. */
export const REASON_LABEL: Record<ReasonCode, string> = {
  operator_manual: "Operator decision",
  max_lifetime: "Reached its lifetime",
  idle: "Idle",
  reverse_shell: "Reverse shell seen",
  egress_blocked: "Egress blocked",
  yara_match: "YARA match",
  canary_used: "Canary credential used",
  honeyscore_high: "Honeyscore high (fingerprinted)",
  health_failed: "Health check failed",
};

export const REASON_CODES = Object.keys(REASON_LABEL) as ReasonCode[];
