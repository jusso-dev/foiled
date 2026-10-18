/**
 * Launch wizard rules (docs/ui/console.md#launch-wizard). The API enforces
 * all of these again; checking them here lets the wizard explain a refusal
 * before the operator confirms.
 */

import type { AgentRecord, CatalogueEntry, CreateDecoy } from "./api-types";

export const LIFETIMES: readonly { seconds: number; label: string }[] = [
  { seconds: 3600, label: "1 hour" },
  { seconds: 6 * 3600, label: "6 hours" },
  { seconds: 24 * 3600, label: "24 hours (default)" },
  { seconds: 3 * 24 * 3600, label: "3 days" },
  { seconds: 7 * 24 * 3600, label: "7 days (the maximum)" },
];
export const DEFAULT_LIFETIME = 24 * 3600;

export const KIND_NOTE = {
  sandbox:
    "Runs the real, vulnerable software in an isolated sandbox with deny-by-default egress. Placed on a research host, or on an edge sensor that allows sandboxes.",
  emulation:
    "Runs an emulator profile that imitates the product. No vulnerable code runs. Can be placed on any edge sensor.",
} as const;

export interface LaunchConfig {
  entryId: string;
  label?: string;
  lifetime: number;
  placement: "pool" | "sensor";
  sensorId?: string;
  allowDraft: boolean;
}

export interface LaunchCheck {
  config: LaunchConfig;
  /** Field name to message. Empty when the launch may go ahead. */
  errors: Record<string, string>;
}

function get(src: URLSearchParams | FormData, name: string, max: number): string | undefined {
  const v = src.get(name);
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t ? t.slice(0, max) : undefined;
}

/** Whether a sensor can take this entry. */
export function sensorFits(entry: CatalogueEntry, sensor: AgentRecord): string | null {
  if (sensor.status === "revoked") return "is revoked";
  if (entry.decoy_kind === "sandbox" && !sensor.sandbox_allowed) return "does not allow sandboxes";
  return null;
}

/**
 * Read and check the wizard's settings for one entry, from the confirm
 * step's query string or the final form post.
 */
export function checkLaunch(
  src: URLSearchParams | FormData,
  entry: CatalogueEntry,
  sensors: readonly AgentRecord[],
  canElevate: boolean,
): LaunchCheck {
  const errors: Record<string, string> = {};
  const label = get(src, "label", 200);
  if (label !== undefined && label.length > 100) errors.label = "Use 100 characters or fewer.";

  const lifetimeRaw = get(src, "lifetime", 10);
  const lifetime = lifetimeRaw === undefined ? DEFAULT_LIFETIME : Number(lifetimeRaw);
  if (!LIFETIMES.some((l) => l.seconds === lifetime)) errors.lifetime = "Pick a listed lifetime.";

  const placement = get(src, "placement", 10) === "sensor" ? "sensor" : "pool";
  const sensorId = placement === "sensor" ? get(src, "sensor", 128) : undefined;
  if (placement === "sensor") {
    const sensor = sensors.find((s) => s.id === sensorId);
    if (!sensorId || !sensor) {
      errors.sensor = "Pick one of your edge sensors.";
    } else {
      const why = sensorFits(entry, sensor);
      if (why) errors.sensor = `That sensor ${why}.`;
    }
  }

  const allowDraft = get(src, "allow_draft", 3) === "yes";
  if (entry.status === "deprecated") {
    errors.entry = "Deprecated entries cannot be launched.";
  } else if (entry.status === "draft") {
    if (!allowDraft) errors.allow_draft = "Draft entries need an explicit opt-in.";
    else if (!canElevate) errors.allow_draft = "Draft entries need the decoys:elevate scope.";
  }

  return {
    config: {
      entryId: entry.id,
      label,
      lifetime,
      placement,
      sensorId,
      allowDraft: entry.status === "draft" && allowDraft,
    },
    errors,
  };
}

export function createBody(c: LaunchConfig): CreateDecoy {
  const body: CreateDecoy = { catalogue_id: c.entryId, lifetime_seconds: c.lifetime };
  if (c.label) body.label = c.label;
  if (c.allowDraft) body.allow_draft = true;
  if (c.placement === "sensor" && c.sensorId) body.sensor_id = c.sensorId;
  return body;
}

/** The confirm step's query string, so "Change settings" can go back with them. */
export function configQuery(c: LaunchConfig): string {
  const p = new URLSearchParams({ entry: c.entryId, lifetime: String(c.lifetime) });
  if (c.label) p.set("label", c.label);
  p.set("placement", c.placement);
  if (c.sensorId) p.set("sensor", c.sensorId);
  if (c.allowDraft) p.set("allow_draft", "yes");
  return p.toString();
}

export function lifetimeLabel(seconds: number): string {
  return (
    LIFETIMES.find((l) => l.seconds === seconds)?.label.replace(/ \(.*\)$/, "") ?? `${seconds}s`
  );
}
