import { Link } from "react-router";
import { ConfidenceMeter } from "../components/ConfidenceMeter";
import { Facts, PageHead, Time } from "../components/console/Controls";
import { Notice } from "../components/console/Notice";
import { RouteError } from "../components/console/RouteError";
import { IOC_TYPE_LABEL, IocValue, windowQuery } from "../components/console/Tables";
import { must, requireOperator } from "../lib/console.server";
import { formatCount, words } from "../lib/format";
import { confidenceOf, SOURCE_LABEL } from "../lib/links";
import { toPrintable } from "../lib/printable";
import type { Route } from "./+types/ioc";

export function meta({ params }: Route.MetaArgs) {
  return [{ title: `IOC ${params.iocId} · Foiled console` }];
}

export async function loader(args: Route.LoaderArgs) {
  const op = await requireOperator(args);
  const p = new URL(args.request.url).searchParams;
  const n = (k: string) => {
    const v = p.get(k);
    return v && /^\d{1,16}$/.test(v) ? Number(v) : undefined;
  };
  const w = { since: n("since"), until: n("until") };
  const ioc = await must(args.request, op.api.getIoc(args.params.iocId, w));
  return { ioc, window: w };
}

/** Enrichment values are provider data, not attacker text, but still shown as text only. */
function show(v: unknown): string {
  if (v === null || v === undefined) return "";
  return toPrintable(typeof v === "string" ? v : JSON.stringify(v)).slice(0, 200);
}

export default function IocPage({ loaderData: d }: Route.ComponentProps) {
  const i = d.ioc;
  const conf = confidenceOf(i.confidence);
  const wq = windowQuery(d.window);
  const sentence =
    conf.level === "confirmed"
      ? `Confirmed by an analyst. Score ${conf.score} of 100.`
      : `We assess as an indicator from these attempts. Score ${conf.score} of 100, not confirmed by an analyst.`;
  return (
    <>
      <PageHead title={<IocValue ioc={i} />}>
        <span className="tag">{IOC_TYPE_LABEL[i.type] ?? i.type}</span>{" "}
        <span className="mono muted">{i.ioc_id}</span>
      </PageHead>
      {i.redacted ? (
        <Notice kind="info">
          <p>Secrets or personal information were removed from this value before storage.</p>
        </Notice>
      ) : null}
      {i.file_ioc_limited ? (
        <Notice kind="info">
          <p>
            An attempt this was seen in reached post-exploitation without a captured file. File
            hashes are missing on purpose; none is invented.
          </p>
        </Notice>
      ) : null}
      <div className="split">
        <section className="card panel" aria-label="Indicator">
          <header className="panel__head">
            <h2 className="panel__title">Indicator</h2>
          </header>
          <div className="panel__body">
            <Facts
              items={[
                ["Value (defanged)", <IocValue ioc={i} />],
                ["Roles", i.roles.map(words).join(", ")],
                [
                  "Origin",
                  i.origin === "observed"
                    ? "Seen by a Foiled decoy"
                    : "Enrichment pivot (never shared)",
                ],
                ["First seen", <Time ms={i.first_seen} />],
                ["Last seen", <Time ms={i.last_seen} />],
                ["Sightings", formatCount(i.sightings)],
                [
                  "Read from",
                  <span className="mono">{i.extracted_from.map(toPrintable).join(", ")}</span>,
                ],
              ]}
            />
            {i.fingerprint ? (
              <>
                <h3 className="explain__h">Behaviour fingerprint steps</h3>
                <ol className="bullets mono">
                  {i.fingerprint.steps.map((s, n) => (
                    <li key={`${n}-${s}`}>{toPrintable(s)}</li>
                  ))}
                </ol>
              </>
            ) : null}
            {i.enrichment.length ? (
              <>
                <h3 className="explain__h">Context</h3>
                <ul className="bullets">
                  {i.enrichment.map((e) => (
                    <li key={`${e.provider}-${e.key}`}>
                      <span className="mono">{toPrintable(e.key)}</span>: {show(e.value)}{" "}
                      <span className="muted">
                        ({toPrintable(e.provider)}
                        {e.shareable ? "" : ", not shareable"})
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        </section>
        <ConfidenceMeter
          level={conf.level}
          score={conf.score}
          subject={i.ioc_id}
          wording={sentence}
          evidence={i.confidence.evidence.map((e) => ({
            id: e.signal_id,
            signal: toPrintable(e.summary),
            source: SOURCE_LABEL[e.source] ?? e.source,
            points: e.weight,
          }))}
        />
      </div>
      {i.confidence.caps_applied.length ? (
        <p className="hint">Caps: {i.confidence.caps_applied.map(toPrintable).join("; ")}.</p>
      ) : null}
      <p className="hint">
        The ledger lists each evidence item's weight.{" "}
        {i.confidence.publishable
          ? "Publishable in exports."
          : "Not publishable: stays internal unless an unreviewed export is requested."}
      </p>
      <section className="card panel" aria-label="Seen in">
        <header className="panel__head">
          <h2 className="panel__title">Seen in</h2>
        </header>
        <div className="panel__body">
          <h3 className="explain__h">Attempts ({i.attempt_ids.length})</h3>
          <ul className="bullets mono">
            {i.attempt_ids.slice(0, 50).map((a) => (
              <li key={a}>
                <Link className="link" to={`/attempts/${a}${wq}`}>
                  {a}
                </Link>
              </li>
            ))}
          </ul>
          {i.campaign_ids.length ? (
            <>
              <h3 className="explain__h">Campaigns</h3>
              <ul className="bullets mono">
                {i.campaign_ids.map((c) => (
                  <li key={c}>
                    <Link className="link" to={`/campaigns/${c}${wq}`}>
                      {c}
                    </Link>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          <p className="hint">
            Decoys: <span className="mono">{i.decoy_ids.map(toPrintable).join(", ")}</span>
          </p>
        </div>
      </section>
    </>
  );
}

export function ErrorBoundary() {
  return <RouteError what="IOC" />;
}
