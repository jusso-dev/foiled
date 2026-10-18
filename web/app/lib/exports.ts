/**
 * Export downloads (#13, docs/intel-outputs.md once #13 lands). The console
 * proxies the API's download through the Worker so the token stays
 * server-side, and names the file with its TLP and review markers.
 */

import type { Tlp } from "./api-types";

export type ExportFormat = "source-csv" | "ioc-csv" | "ioc-json" | "stix" | "misp";

export const EXPORT_FORMATS: Record<
  ExportFormat,
  {
    label: string;
    path: string;
    ext: string;
    type: string;
    fixed?: Record<string, string>;
    gated: boolean;
  }
> = {
  "source-csv": {
    label: "Source IP CSV (one row per source address)",
    path: "/v0/exports/iocs.csv",
    ext: "csv",
    type: "text/csv; charset=utf-8",
    gated: false,
  },
  "ioc-csv": {
    label: "IOC CSV (one row per indicator)",
    path: "/v0/exports/iocs.csv",
    ext: "csv",
    type: "text/csv; charset=utf-8",
    fixed: { fields: "ioc" },
    gated: true,
  },
  "ioc-json": {
    label: "IOC JSON",
    path: "/v0/exports/iocs.json",
    ext: "json",
    type: "application/json",
    gated: true,
  },
  stix: {
    label: "STIX 2.1 bundle",
    path: "/v0/exports/stix",
    ext: "stix.json",
    type: "application/stix+json;version=2.1",
    gated: true,
  },
  misp: {
    label: "MISP event",
    path: "/v0/exports/misp",
    ext: "misp.json",
    type: "application/json",
    gated: true,
  },
};

export const TLPS: readonly Tlp[] = ["clear", "green", "amber", "amber+strict", "red"];

/** Unreviewed exports are raised to at least TLP:AMBER+STRICT by the API; show the same here. */
export function effectiveTlp(tlp: Tlp, unreviewed: boolean): Tlp {
  if (!unreviewed) return tlp;
  return tlp === "red" ? "red" : "amber+strict";
}

/** `foiled-stix-tlp-amber-20261018-unreviewed-partial.stix.json` */
export function exportFilename(
  format: ExportFormat,
  tlp: Tlp,
  opts: { unreviewed: boolean; partial: boolean; now: number },
): string {
  const d = new Date(opts.now);
  const day = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
  const parts = ["foiled", format, `tlp-${tlp.replace("+", "-")}`, day];
  if (opts.unreviewed) parts.push("unreviewed");
  if (opts.partial) parts.push("partial");
  return `${parts.join("-")}.${EXPORT_FORMATS[format].ext}`;
}
