import { useState } from "react";
import { AppShell } from "../components/AppShell";
import { AttackHeatmap } from "../components/AttackHeatmap";
import { AttackMap } from "../components/AttackMap";
import { AttemptTimeline } from "../components/AttemptTimeline";
import { ConfidenceChip } from "../components/ConfidenceChip";
import { ConfidenceMeter } from "../components/ConfidenceMeter";
import { CveRef } from "../components/CveRef";
import { ExploitTable } from "../components/ExploitTable";
import { IocTable } from "../components/IocTable";
import { KpiCard } from "../components/KpiCard";
import { Panel } from "../components/Panel";
import { RankedBarTable } from "../components/RankedBarTable";
import { RawRequestBlock } from "../components/RawRequestBlock";
import { SegmentedToggle } from "../components/SegmentedToggle";
import { Sparkline } from "../components/Sparkline";
import { TrendTable } from "../components/TrendTable";
import * as ex from "../fixtures/example-data";
import type { Route } from "./+types/design";

export function meta(_: Route.MetaArgs) {
  return [
    { title: "Design system (example data) · Foiled" },
    { name: "robots", content: "noindex" },
  ];
}

/**
 * Static showcase of every console component, laid out like mockup-v3.
 * All data on this page is EXAMPLE DATA from app/fixtures/example-data.ts.
 */
export default function Design() {
  const [demoToggle, setDemoToggle] = useState<"a" | "b" | "c">("a");
  return (
    <AppShell activeNav="live-attacks" counts={ex.navCounts} exampleData>
      <div className="design-kpis">
        {ex.kpis.map((k) => (
          <KpiCard key={k.label} {...k} />
        ))}
      </div>

      <div className="design-grid">
        <div className="design-grid__map">
          <AttackMap
            title="Live attacks"
            subtitle="Exploit attempts against Foiled sensors · example data"
            hotspots={ex.hotspots}
            sensors={ex.sensors}
            arcs={ex.arcs}
            hits={ex.hits}
          />
        </div>

        <div className="design-grid__rail">
          <Panel title="Top attacker IPs">
            <RankedBarTable
              caption="Top attacker IPs, example data"
              rows={ex.attackerIps}
              labelHeader="IP address"
              tagHeader="CC"
              valueHeader="Attempts"
              monoLabel
            />
          </Panel>
          <Panel title="Targeted technologies">
            <RankedBarTable
              caption="Targeted technologies, example data"
              rows={ex.technologies}
              labelHeader="Technology"
              valueHeader="Share"
              format="percent"
            />
          </Panel>
          <Panel title="Attacker countries" action={{ label: "View all", href: "#attackers" }}>
            <TrendTable
              caption="Attacker countries, example data"
              rows={ex.countries}
              labelHeader="Country"
              valueHeader="Attempts"
              showChange={false}
              badgeStyle="square"
              sparkWidth={60}
            />
          </Panel>
        </div>

        <div className="design-grid__bottom">
          <Panel title="Recent exploits" action={{ label: "View all", href: "#exploit-activity" }}>
            <ExploitTable caption="Recent exploits, example data" rows={ex.recentExploits} />
          </Panel>
          <Panel title="Malware payloads" action={{ label: "View all", href: "#malware" }}>
            <TrendTable
              caption="Malware payloads, example data"
              rows={ex.malware}
              labelHeader="Name"
              valueHeader="Seen"
            />
          </Panel>
        </div>
      </div>

      <h2 className="design-section">Detail views · example data</h2>
      <div className="design-detail">
        <ConfidenceMeter
          level="assessed"
          score={64}
          subject="CVE-2099-EXAMPLE1"
          evidence={ex.evidence}
        />
        <Panel title="Attempt timeline">
          <AttemptTimeline label="Attempt timeline, example data" events={ex.timeline} />
        </Panel>
        <Panel title="ATT&CK techniques by hour" className="design-detail__wide">
          <AttackHeatmap
            caption="ATT&CK technique counts by four-hour window, example data"
            columns={ex.heatmapColumns}
            techniques={ex.heatmap}
          />
        </Panel>
        <Panel title="IOCs" className="design-detail__wide">
          <IocTable caption="Indicators of compromise, example data" rows={ex.iocs} />
        </Panel>
        <div className="design-detail__wide">
          <RawRequestBlock raw={ex.rawRequest} meta="HTTP · example data" maxChars={720} />
        </div>
      </div>

      <h2 className="design-section">Primitives · example data</h2>
      <div className="design-primitives card">
        <dl>
          <dt>Confidence chip</dt>
          <dd className="design-row">
            <ConfidenceChip level="assessed" score={64} />
            <ConfidenceChip level="probable" score={81} />
            <ConfidenceChip level="confirmed" score={96} />
          </dd>
          <dt>CVE reference (chip required)</dt>
          <dd className="design-row">
            <CveRef id="CVE-2099-EXAMPLE1" confidence={{ level: "assessed", score: 64 }} />
            <CveRef id="FOILED-DEMO-0001" confidence={{ level: "probable", score: 70 }} />
          </dd>
          <dt>Segmented toggle</dt>
          <dd className="design-row">
            <SegmentedToggle
              label="Example toggle"
              options={[
                { value: "a", label: "Attempts" },
                { value: "b", label: "Sources" },
                { value: "c", label: "CVEs" },
              ]}
              value={demoToggle}
              onChange={setDemoToggle}
            />
          </dd>
          <dt>Sparkline</dt>
          <dd className="design-row">
            <Sparkline values={ex.exampleSeries(11)} label="Example attempts, rising" />
            <Sparkline values={ex.exampleSeries(12, 24, false)} stroke="var(--green)" />
          </dd>
        </dl>
      </div>

      <p className="design-foot mono">
        Foiled design system · all figures, IPs (RFC 5737 192.0.2.0/24, 198.51.100.0/24,
        203.0.113.0/24), CVE ids and technologies are invented examples · map land: Natural Earth
        (public domain)
      </p>
    </AppShell>
  );
}
