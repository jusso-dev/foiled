import { redirect } from "react-router";
import type { QueryValue } from "../lib/api.server";
import type { DecoyKind, Tlp } from "../lib/api-types";
import { intField, load, oneOf, requireMutation } from "../lib/console.server";
import {
  EXPORT_FORMATS,
  type ExportFormat,
  effectiveTlp,
  exportFilename,
  TLPS,
} from "../lib/exports";
import { isId } from "../lib/ids";
import type { Route } from "./+types/exports.download";

export function loader() {
  return redirect("/exports");
}

const FORMATS = Object.keys(EXPORT_FORMATS) as ExportFormat[];

/**
 * Proxy one export download. A POST so it carries the CSRF token: unreviewed
 * exports are audited by the API, so a download is a write as far as the
 * console is concerned.
 */
export async function action(args: Route.ActionArgs) {
  const op = await requireMutation(args);
  const f = op.form;
  const format = oneOf(f, "format", FORMATS);
  if (!format) return redirect("/exports?failed=400");
  const spec = EXPORT_FORMATS[format];
  const tlp = oneOf(f, "tlp", TLPS) ?? "amber";
  const unreviewed = spec.gated && f.get("include_unreviewed") === "yes";
  const days = intField(f, "days", 1, 31) ?? 7;
  const now = Date.now();
  const q: Record<string, QueryValue> = { since: now - days * 24 * 3600_000, ...spec.fixed };
  if (spec.gated) {
    q.until = now;
    q.tlp = tlp;
    q.min_confidence = intField(f, "min_confidence", 0, 100);
    q.state = oneOf(f, "state", ["probe", "exploit", "post-exploitation"] as const);
    q.decoy_kind = oneOf(f, "decoy_kind", ["sandbox", "emulation"] as DecoyKind[]);
    const campaign = f.get("campaign_id");
    if (isId("campaign", campaign)) q.campaign_id = campaign;
    if (unreviewed) q.include_unreviewed = true;
    if (f.get("include_actors") === "yes") q.include_actors = true;
    if (f.get("include_payloads") === "yes") q.include_payloads = true;
  }
  const res = await load(args.request, op.api.exportDownload(spec.path, q));
  if (!res.ok) {
    const back = new URLSearchParams({ failed: String(res.error.status), format });
    if (res.error.notServed) back.set("not_served", "1");
    return redirect(`/exports?${back}`);
  }
  const upstream = res.data;
  const partial = upstream.headers.get("x-foiled-truncated") === "true";
  const name = exportFilename(format, effectiveTlp(tlp as Tlp, unreviewed), {
    unreviewed,
    partial,
    now,
  });
  const headers = new Headers({
    "content-type": upstream.headers.get("content-type") ?? spec.type,
    "content-disposition": `attachment; filename="${name}"`,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  for (const h of ["x-foiled-truncated", "x-foiled-next-cursor"]) {
    const v = upstream.headers.get(h);
    if (v) headers.set(h, v.slice(0, 1100));
  }
  return new Response(upstream.body, { status: 200, headers });
}
