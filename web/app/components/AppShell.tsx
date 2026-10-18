import { type FormEvent, type ReactNode, useId, useState } from "react";
import { FoiledMark, Icon, type IconName } from "./icons";
import { NavItem } from "./NavItem";
import { SegmentedToggle, type SegmentOption } from "./SegmentedToggle";

export type NavId =
  | "live-attacks"
  | "exploit-activity"
  | "malware"
  | "cve-intelligence"
  | "attackers"
  | "targeted-tech"
  | "honeypots"
  | "payloads"
  | "iocs"
  | "attack-ttps"
  | "reports"
  | "api-mcp";

export const NAV_ITEMS: readonly { id: NavId; label: string; icon: IconName }[] = [
  { id: "live-attacks", label: "Live Attacks", icon: "live" },
  { id: "exploit-activity", label: "Exploit Activity", icon: "activity" },
  { id: "malware", label: "Malware", icon: "malware" },
  { id: "cve-intelligence", label: "CVE Intelligence", icon: "cve" },
  { id: "attackers", label: "Attackers", icon: "attackers" },
  { id: "targeted-tech", label: "Targeted Tech", icon: "tech" },
  { id: "honeypots", label: "Honeypots", icon: "honeypots" },
  { id: "payloads", label: "Payloads", icon: "payloads" },
  { id: "iocs", label: "IOCs", icon: "iocs" },
  { id: "attack-ttps", label: "ATT&CK TTPs", icon: "ttps" },
  { id: "reports", label: "Reports", icon: "reports" },
  { id: "api-mcp", label: "API & MCP", icon: "api" },
];

export type TimeRange = "1h" | "24h" | "7d" | "30d";
export const TIME_RANGES: readonly SegmentOption<TimeRange>[] = [
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
];

export type Region = "global" | "au" | "apac" | "eu" | "na" | "sa";
export const REGIONS: readonly { value: Region; label: string }[] = [
  { value: "global", label: "Global" },
  { value: "au", label: "Australia (AU)" },
  { value: "apac", label: "Asia Pacific" },
  { value: "eu", label: "Europe" },
  { value: "na", label: "North America" },
  { value: "sa", label: "South America" },
];

export interface AppShellProps {
  children: ReactNode;
  activeNav?: NavId;
  /** Count badges per nav item. */
  counts?: Partial<Record<NavId, number>>;
  /** Link target per nav item. Defaults to an in-page anchor. */
  hrefFor?: (id: NavId) => string;
  defaultTimeRange?: TimeRange;
  defaultRegion?: Region;
  onTimeRangeChange?: (range: TimeRange) => void;
  onRegionChange?: (region: Region) => void;
  onSearch?: (query: string) => void;
  /** Whether the live stream is connected. */
  live?: boolean;
  /** Show the amber EXAMPLE DATA banner and sidebar tag. */
  exampleData?: boolean;
}

export function AppShell({
  children,
  activeNav = "live-attacks",
  counts = {},
  hrefFor = (id) => `#${id}`,
  defaultTimeRange = "24h",
  defaultRegion = "au",
  onTimeRangeChange,
  onRegionChange,
  onSearch,
  live = false,
  exampleData = false,
}: AppShellProps) {
  const [range, setRange] = useState<TimeRange>(defaultTimeRange);
  const [region, setRegion] = useState<Region>(defaultRegion);
  const searchId = useId();
  const regionId = useId();

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const q = new FormData(e.currentTarget).get("q");
    onSearch?.(typeof q === "string" ? q.trim() : "");
  }

  return (
    <div className="shell">
      <aside className="shell__side">
        <div className="brand">
          <FoiledMark />
          <div>
            <div className="brand__wordmark">FOILED</div>
            <div className="brand__tag">Exploit intelligence</div>
          </div>
        </div>
        <nav aria-label="Main">
          <ul className="nav">
            {NAV_ITEMS.map((item) => (
              <li key={item.id}>
                <NavItem
                  label={item.label}
                  href={hrefFor(item.id)}
                  icon={item.icon}
                  count={counts[item.id]}
                  active={item.id === activeNav}
                />
              </li>
            ))}
          </ul>
        </nav>
        <p className="motto">
          Real attackers.
          <br />
          Real behaviour.
          <br />
          <strong>Assessed, not guessed.</strong>
        </p>
        {exampleData ? <p className="example-tag">EXAMPLE DATA · NOT REAL TELEMETRY</p> : null}
      </aside>

      <div className="shell__main">
        <header className="topbar">
          <form className="search" aria-label="Search" onSubmit={submit}>
            <label htmlFor={searchId} className="sr-only">
              Search
            </label>
            <Icon name="search" size={16} />
            <input
              id={searchId}
              name="q"
              type="search"
              autoComplete="off"
              placeholder="Search IPs, CVEs, sandboxes, payloads, ATT&CK IDs..."
            />
          </form>
          <SegmentedToggle
            className="topbar__range"
            label="Time range"
            options={TIME_RANGES}
            value={range}
            onChange={(v) => {
              setRange(v);
              onTimeRangeChange?.(v);
            }}
          />
          <div className={region === "au" ? "region region--au" : "region"}>
            <label htmlFor={regionId}>Region:</label>
            <select
              id={regionId}
              value={region}
              onChange={(e) => {
                const v = e.currentTarget.value as Region;
                setRegion(v);
                onRegionChange?.(v);
              }}
            >
              {REGIONS.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>
          <LiveIndicator live={live} />
          {exampleData ? <span className="example-banner">EXAMPLE DATA</span> : null}
        </header>
        <main className="shell__content">{children}</main>
      </div>
    </div>
  );
}

/** The live dot is one of only two places glow is allowed (the other is map hotspots). */
export function LiveIndicator({ live }: { live: boolean }) {
  return (
    <output className={live ? "live live--on" : "live"} aria-live="polite">
      <span className="live__dot" aria-hidden="true" />
      {live ? "Live" : "Paused"}
    </output>
  );
}
