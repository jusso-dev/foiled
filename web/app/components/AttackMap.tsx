import { useId, useState } from "react";
import { LAND_COLS, LAND_RLE, LAND_ROWS } from "./map/world-land";
import { SegmentedToggle } from "./SegmentedToggle";

/** Map canvas size in SVG units (equirectangular, 1000 x 500 for the whole globe). */
export const MAP_W = 1000;
export const MAP_H = 500;
/** Default crop: roughly 80N to 58S, as in mockup-v3. */
const VIEW_Y = 28;
const VIEW_H = 383;

export interface GeoPoint {
  lon: number;
  lat: number;
}

/** Source cluster. Rendered with glow, sized by weight (0 to 1). */
export interface MapHotspot extends GeoPoint {
  id: string;
  label: string;
  weight: number;
}

/** A Foiled sensor that received attempts. */
export interface MapSensor extends GeoPoint {
  id: string;
  label: string;
  hits: number;
  /** Draw a labelled callout box, for example "SYD-EDGE-03 · 88". */
  callout?: boolean;
}

/** Small scatter dot for an individual attempt source. No glow. */
export interface MapHit extends GeoPoint {
  id: string;
  /** Opacity from 0 to 1. */
  intensity?: number;
}

export interface MapArc {
  from: string; // hotspot id
  to: string; // sensor id
}

export type MapView = "map" | "globe" | "heatmap" | "au";

const VIEWS = [
  { value: "map", label: "Map" },
  { value: "globe", label: "Globe", hint: "coming soon" },
  { value: "heatmap", label: "Heatmap", hint: "coming soon" },
  { value: "au", label: "AU", hint: "coming soon" },
] as const;

export interface AttackMapProps {
  title?: string;
  subtitle?: string;
  hotspots: readonly MapHotspot[];
  sensors?: readonly MapSensor[];
  arcs?: readonly MapArc[];
  hits?: readonly MapHit[];
  /** Panel height in px. */
  height?: number;
}

/** Equirectangular projection into the 1000 x 500 map canvas. */
export function project({ lon, lat }: GeoPoint): [number, number] {
  return [((lon + 180) / 360) * MAP_W, ((90 - lat) / 180) * MAP_H];
}

const r1 = (n: number) => Math.round(n * 10) / 10;

/** SVG path of land cells from the embedded run-length mask, built once. */
export function landPath(rows: readonly string[] = LAND_RLE): string {
  const cw = MAP_W / LAND_COLS;
  const ch = MAP_H / LAND_ROWS;
  let d = "";
  rows.forEach((row, r) => {
    if (!row) return;
    const runs = row.split(" ").map(Number);
    let col = 0;
    for (let i = 0; i < runs.length; i++) {
      if (i % 2 === 1) {
        d += `M${r1(col * cw)} ${r1(r * ch)}h${r1(runs[i] * cw)}v${r1(ch)}h${r1(-runs[i] * cw)}z`;
      }
      col += runs[i];
    }
  });
  return d;
}

const LAND = landPath();

function arcPath(from: [number, number], to: [number, number], weight: number): string {
  const mx = (from[0] + to[0]) / 2;
  const my = Math.min(from[1], to[1]) - 140 * weight;
  return `M${r1(from[0])} ${r1(from[1])}Q${r1(mx)} ${r1(my)} ${r1(to[0])} ${r1(to[1])}`;
}

/**
 * Live attack map. Server-rendered SVG: dotted land, scatter hits, glowing
 * source clusters, arcs to sensors and sensor callouts. Only the Map view is
 * built; Globe, Heatmap and AU are selectable and show "coming soon".
 * Props drive everything, so a live-stream client can re-render with new points.
 */
export function AttackMap({
  title = "Live attacks",
  subtitle,
  hotspots,
  sensors = [],
  arcs = [],
  hits = [],
  height = 392,
}: AttackMapProps) {
  const [view, setView] = useState<MapView>("map");
  const [zoom, setZoom] = useState(1);
  const uid = `map${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;

  // Zoom towards the sensors (the operator's own fleet), kept inside the map.
  const w = MAP_W / zoom;
  const h = VIEW_H / zoom;
  const focus = sensors.length
    ? sensors
        .map(project)
        .reduce(([ax, ay], [x, y]) => [ax + x / sensors.length, ay + y / sensors.length], [0, 0])
    : [MAP_W / 2, VIEW_Y + VIEW_H / 2];
  const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));
  const cx = clamp(focus[0], w / 2, MAP_W - w / 2);
  const cy = clamp(focus[1], VIEW_Y + h / 2, VIEW_Y + VIEW_H - h / 2);
  const viewBox = `${r1(cx - w / 2)} ${r1(cy - h / 2)} ${r1(w)} ${r1(h)}`;

  const hotById = new Map(hotspots.map((p) => [p.id, p]));
  const sensorById = new Map(sensors.map((s) => [s.id, s]));
  const soon = VIEWS.find((v) => v.value === view && "hint" in v);

  const summary = `${title}: ${hotspots.length} source clusters, ${sensors.length} sensors, ${arcs.length} arcs.`;

  return (
    <section className="card attack-map" aria-label={title}>
      <div className="attack-map__title">
        <span className="live__dot" aria-hidden="true" />
        <div>
          <h2 className="attack-map__h">{title}</h2>
          {subtitle ? <p className="attack-map__sub">{subtitle}</p> : null}
        </div>
      </div>
      <SegmentedToggle
        className="attack-map__views"
        label="Map view"
        options={VIEWS}
        value={view}
        onChange={setView}
      />
      <svg
        className="attack-map__svg"
        viewBox={viewBox}
        preserveAspectRatio="xMidYMid meet"
        width="100%"
        height={height}
        role="img"
        aria-label={summary}
      >
        <defs>
          <pattern id={`${uid}-dots`} width="4" height="4" patternUnits="userSpaceOnUse">
            <circle cx="2" cy="2" r="0.9" className="attack-map__dot" />
          </pattern>
          <clipPath id={`${uid}-land`}>
            <path d={LAND} />
          </clipPath>
          {/* Glow filter: used on hotspots only. */}
          <filter id={`${uid}-glow`} x="-200%" y="-200%" width="500%" height="500%">
            <feGaussianBlur stdDeviation="6" />
          </filter>
        </defs>
        <rect width={MAP_W} height={MAP_H} className="attack-map__sea" />
        <path d={LAND} className="attack-map__land" />
        <rect
          width={MAP_W}
          height={MAP_H}
          fill={`url(#${uid}-dots)`}
          clipPath={`url(#${uid}-land)`}
        />
        <g className="attack-map__hits">
          {hits.map((p) => {
            const [x, y] = project(p);
            return <circle key={p.id} cx={r1(x)} cy={r1(y)} r={1.4} opacity={p.intensity ?? 0.7} />;
          })}
        </g>
        <g className="attack-map__arcs">
          {arcs.map((a) => {
            const src = hotById.get(a.from);
            const dst = sensorById.get(a.to);
            if (!src || !dst) return null;
            return (
              <path key={`${a.from}-${a.to}`} d={arcPath(project(src), project(dst), src.weight)} />
            );
          })}
        </g>
        {hotspots.map((p) => {
          const [x, y] = project(p);
          const wgt = Math.min(1, Math.max(0, p.weight));
          return (
            <g key={p.id} className="attack-map__hotspot" data-hotspot={p.id}>
              <title>{p.label}</title>
              <circle
                cx={r1(x)}
                cy={r1(y)}
                r={r1(14 * wgt + 6)}
                className="attack-map__halo"
                filter={`url(#${uid}-glow)`}
              />
              <circle cx={r1(x)} cy={r1(y)} r={r1(6 * wgt + 3)} className="attack-map__ring" />
              <circle cx={r1(x)} cy={r1(y)} r={3} className="attack-map__core" />
            </g>
          );
        })}
        {sensors.map((s) => {
          const [x, y] = project(s);
          return (
            <g key={s.id} className="attack-map__sensor" data-sensor={s.id}>
              <title>{`${s.label}: ${s.hits} hits`}</title>
              <rect x={r1(x - 3)} y={r1(y - 3)} width={6} height={6} className="attack-map__box" />
              {s.callout ? (
                <g className="attack-map__callout">
                  <rect x={r1(x - 112)} y={r1(y - 30)} width={96} height={18} rx={3} />
                  <text x={r1(x - 106)} y={r1(y - 17)}>
                    {`${s.label} · ${s.hits}`}
                  </text>
                </g>
              ) : null}
            </g>
          );
        })}
      </svg>
      {soon ? (
        <p className="attack-map__soon" role="status">
          {soon.label} view is coming soon. Showing the flat map.
        </p>
      ) : null}
      <fieldset className="attack-map__zoom">
        <legend className="sr-only">Zoom</legend>
        <button
          type="button"
          aria-label="Zoom in"
          onClick={() => setZoom((z) => Math.min(4, z * 1.5))}
        >
          +
        </button>
        <button
          type="button"
          aria-label="Zoom out"
          onClick={() => setZoom((z) => Math.max(1, z / 1.5))}
        >
          −
        </button>
        <button type="button" aria-label="Reset zoom" onClick={() => setZoom(1)}>
          ◎
        </button>
      </fieldset>
      <p className="attack-map__legend">
        <span aria-hidden="true">●</span> sensor hit &nbsp; <span aria-hidden="true">◯</span> source
        cluster &nbsp; arcs: source → sensor
      </p>
      <ul className="sr-only">
        {hotspots.map((p) => (
          <li key={p.id}>Source cluster: {p.label}</li>
        ))}
        {sensors.map((s) => (
          <li key={s.id}>
            Sensor {s.label}: {s.hits} hits
          </li>
        ))}
      </ul>
    </section>
  );
}
