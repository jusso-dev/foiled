/**
 * Number and time formats from docs/ui/voice.md: `en-AU` thousands
 * separators, `YYYY-MM-DD HH:MM` in UTC, durations as `1m 23s`, offsets
 * inside an attempt as `+0.412s`.
 */

const pad = (n: number, w = 2) => String(n).padStart(w, "0");

/** `2026-10-18 04:02` (UTC). Empty for a missing or invalid time. */
export function formatTs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(
    d.getUTCHours(),
  )}:${pad(d.getUTCMinutes())}`;
}

/** Machine-readable value for a `<time dateTime>` attribute. */
export function isoTs(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/** `+0.412s` for offsets under a minute, `+1m 23s` after. */
export function formatOffset(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "+0.000s";
  if (ms < 60_000) return `+${(ms / 1000).toFixed(3)}s`;
  return `+${formatDuration(ms)}`;
}

/** `45s`, `1m 23s`, `1h 03m`, `2d 04h`. */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "0s";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${pad(s % 60)}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${pad(m % 60)}m`;
  return `${Math.floor(h / 24)}d ${pad(h % 24)}h`;
}

export function formatCount(n: number): string {
  return Number.isFinite(n) ? n.toLocaleString("en-AU") : "0";
}

/** `4.2 MB`, for quarantine sizes. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/** Underscored API enums as words: `post_exploit` to `post exploit`. */
export function words(s: string): string {
  return s.replace(/[_-]+/g, " ");
}
