import type { ReactNode } from "react";

/**
 * Stroke icons drawn for Foiled (from mockup-v3). 24x24 viewBox, decorative:
 * every use sits next to a visible text label.
 */
const PATHS = {
  live: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 1v4M12 19v4M1 12h4M19 12h4" />
    </>
  ),
  activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
  malware: (
    <>
      <circle cx="12" cy="13" r="6" />
      <path d="M12 7V3M7 9 4 6M17 9l3-3M6 14H2M22 14h-4" />
    </>
  ),
  cve: <path d="M4 6h16M4 12h16M4 18h10" />,
  attackers: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21c1-4 4-6 8-6s7 2 8 6" />
    </>
  ),
  tech: <path d="m8 7-5 5 5 5M16 7l5 5-5 5" />,
  honeypots: <path d="M12 3 4 7v6c0 4 3 7 8 8 5-1 8-4 8-8V7z" />,
  payloads: (
    <>
      <rect x="5" y="3" width="14" height="18" rx="2" />
      <path d="M9 8h6M9 12h6M9 16h4" />
    </>
  ),
  iocs: (
    <>
      <circle cx="11" cy="11" r="6" />
      <path d="m20 20-4.5-4.5" />
    </>
  ),
  ttps: (
    <>
      <rect x="3" y="3" width="7" height="7" />
      <rect x="14" y="3" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" />
    </>
  ),
  reports: <path d="M6 3h9l4 4v14H6zM9 13h7M9 17h5" />,
  api: <path d="M10 14 21 3M15 3h6v6M18 14v6H4V6h6" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-4-4" />
    </>
  ),
  bolt: <path d="M14 1 3 16h7l-2 11 13-16h-7z" />,
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" />
    </>
  ),
  bug: (
    <>
      <circle cx="12" cy="13" r="6" />
      <path d="M12 7V4M6 13H2M22 13h-4M7 8 5 6M17 8l2-2M7 18l-2 2M17 18l2 2" />
    </>
  ),
  layers: <path d="M12 2 2 7l10 5 10-5zM2 12l10 5 10-5M2 17l10 5 10-5" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 17 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

/** Hex-framed slashed-F mark from the v3 design direction. Decorative. */
export function FoiledMark({ size = 44 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={(size * 48) / 44}
      viewBox="0 0 44 48"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M22 2 L41 13 V35 L22 46 L3 35 V13 Z"
        fill="none"
        stroke="#E5252A"
        strokeWidth="2.5"
      />
      <path
        d="M22 9 L35 16.5 V31.5 L22 39 L9 31.5 V16.5 Z"
        fill="#1A0809"
        stroke="#7A1114"
        strokeWidth="1.2"
      />
      <path d="M17 16 H28 V20 H21 V23 H26 V27 H21 V33 H17 Z" fill="#FF3B3F" />
      <path d="M12 33 L33 15" stroke="#0B0C0F" strokeWidth="2.4" />
    </svg>
  );
}
