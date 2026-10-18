import { Link } from "react-router";
import type { Attempt, Decoy, Ioc, IocType } from "../../lib/api-types";
import { formatCount, words } from "../../lib/format";
import { confidenceOf } from "../../lib/links";
import { middleEllipsis, toPrintable } from "../../lib/printable";
import { ConfidenceChip } from "../ConfidenceChip";
import { AttemptStateTag, DecoyStateTag, Time } from "./Controls";

/** Query string that carries a list page's window to detail pages. */
export function windowQuery(w: { since?: number; until?: number }): string {
  const p = new URLSearchParams();
  if (w.since !== undefined) p.set("since", String(w.since));
  if (w.until !== undefined) p.set("until", String(w.until));
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function AttemptsTable({
  items,
  caption,
  window = {},
}: {
  items: readonly Attempt[];
  caption: string;
  window?: { since?: number; until?: number };
}) {
  const wq = windowQuery(window);
  return (
    <div className="table-wrap">
      <table className="data-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Last seen</th>
            <th scope="col">Attempt</th>
            <th scope="col">Source</th>
            <th scope="col">Decoy</th>
            <th scope="col">State</th>
            <th scope="col" className="num">
              Hook hits
            </th>
            <th scope="col">Noise</th>
            <th scope="col">Campaign</th>
          </tr>
        </thead>
        <tbody>
          {items.map((a) => (
            <tr key={a.attempt_id}>
              <td className="mono muted">
                <Time ms={a.last_seen} />
              </td>
              <td className="mono">
                <Link className="link" to={`/attempts/${a.attempt_id}${wq}`}>
                  {a.attempt_id}
                </Link>
              </td>
              <td className="mono">{toPrintable(a.src)}</td>
              <td className="wrap">
                <span className="mono">{toPrintable(a.catalogue_id)}</span>{" "}
                <span className="tag">{a.decoy_kind}</span>
              </td>
              <td>
                <AttemptStateTag state={a.state} />
              </td>
              <td className="num mono">{a.hook_hits.length}</td>
              <td className="muted">{a.noise ? `${a.noise.band} (${a.noise.score})` : "n/a"}</td>
              <td className="mono">
                {a.campaign_id ? (
                  <Link className="link" to={`/campaigns/${a.campaign_id}${wq}`}>
                    {a.campaign_id}
                  </Link>
                ) : (
                  <span className="muted">none</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const IOC_TYPE_LABEL: Record<IocType, string> = {
  ip: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  http_path: "HTTP path",
  http_ua: "User agent",
  request_substring: "Request string",
  payload_sha256: "Payload SHA-256",
  file_sha256: "File SHA-256",
  cmdline: "Command line",
  dns_query: "DNS query",
  behaviour_fingerprint: "Behaviour fingerprint",
};

/**
 * IOC value as an analyst sees it: the API's defanged `display`, made
 * printable, shortened in the middle with the full value one click away.
 * The exact `value` is never rendered.
 */
export function IocValue({ ioc }: { ioc: Pick<Ioc, "display"> }) {
  const safe = toPrintable(ioc.display);
  if (safe.length <= 48) return <span className="mono">{safe}</span>;
  return (
    <details className="ioc-value">
      <summary className="mono">{middleEllipsis(safe, 48)}</summary>
      <span className="ioc-value__full mono">{safe}</span>
    </details>
  );
}

export function IocRowsTable({
  items,
  caption,
  window = {},
}: {
  items: readonly Ioc[];
  caption: string;
  window?: { since?: number; until?: number };
}) {
  const wq = windowQuery(window);
  return (
    <div className="table-wrap">
      <table className="data-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Type</th>
            <th scope="col">Value (defanged)</th>
            <th scope="col">Roles</th>
            <th scope="col">Last seen</th>
            <th scope="col" className="num">
              Sightings
            </th>
            <th scope="col" className="num">
              Attempts
            </th>
            <th scope="col">Confidence</th>
            <th scope="col">
              <span className="sr-only">Detail</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((i) => {
            const c = confidenceOf(i.confidence);
            return (
              <tr key={i.ioc_id}>
                <td>
                  <span className="tag">{IOC_TYPE_LABEL[i.type] ?? i.type}</span>
                </td>
                <td className="wrap">
                  <IocValue ioc={i} />
                  {i.redacted ? <span className="muted"> (redacted)</span> : null}
                </td>
                <td className="muted">{i.roles.map(words).join(", ")}</td>
                <td className="mono muted">
                  <Time ms={i.last_seen} />
                </td>
                <td className="num mono">{formatCount(i.sightings)}</td>
                <td className="num mono">{formatCount(i.attempt_ids.length)}</td>
                <td>
                  <ConfidenceChip
                    level={c.level}
                    score={c.score}
                    wording={
                      c.level === "confirmed"
                        ? `Confirmed by an analyst. Score ${c.score} of 100.`
                        : `We assess as an indicator from these attempts. Score ${c.score} of 100, not confirmed by an analyst.`
                    }
                  />
                </td>
                <td>
                  <Link className="link" to={`/iocs/${i.ioc_id}${wq}`}>
                    Detail<span className="sr-only"> for {i.ioc_id}</span>
                  </Link>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function DecoysTable({ items, caption }: { items: readonly Decoy[]; caption: string }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Decoy</th>
            <th scope="col">Label</th>
            <th scope="col">Catalogue entry</th>
            <th scope="col">Kind</th>
            <th scope="col">State</th>
            <th scope="col">Placed on</th>
            <th scope="col">Expires</th>
          </tr>
        </thead>
        <tbody>
          {items.map((d) => (
            <tr key={d.id}>
              <td className="mono">
                <Link className="link" to={`/decoys/${encodeURIComponent(d.id)}`}>
                  {d.id}
                </Link>
              </td>
              <td className="wrap">
                {d.label ? toPrintable(d.label) : <span className="muted">none</span>}
              </td>
              <td className="mono">{d.catalogue_id}</td>
              <td>
                <span className="tag">{d.decoy_kind}</span>
              </td>
              <td>
                <DecoyStateTag state={d.state} />
              </td>
              <td className="mono muted">{d.host_id ?? "not placed yet"}</td>
              <td className="mono muted">
                <Time ms={d.expires_at} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
