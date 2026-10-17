export interface SparklineProps {
  values: readonly number[];
  width?: number;
  height?: number;
  /** Stroke colour. Defaults to the primary red. */
  stroke?: string;
  /** Accessible summary. Without it the sparkline is decorative. */
  label?: string;
  className?: string;
}

/**
 * SVG path for a sparkline. Values are scaled to fit inside `pad` pixels of
 * the box; larger values sit higher. A flat series draws a centred line.
 */
export function sparklinePath(
  values: readonly number[],
  width: number,
  height: number,
  pad = 2,
): string {
  const finite = values.filter((v) => Number.isFinite(v));
  if (finite.length === 0) return "";
  const min = Math.min(...finite);
  const max = Math.max(...finite);
  const span = max - min;
  const innerH = Math.max(0, height - pad * 2);
  const y = (v: number) => (span === 0 ? height / 2 : pad + innerH - ((v - min) / span) * innerH);
  if (finite.length === 1)
    return `M0 ${round(y(finite[0]))}L${round(width)} ${round(y(finite[0]))}`;
  const stepX = width / (finite.length - 1);
  return `M${finite.map((v, i) => `${round(i * stepX)} ${round(y(v))}`).join("L")}`;
}

function round(n: number): string {
  return String(Math.round(n * 10) / 10);
}

export function Sparkline({
  values,
  width = 120,
  height = 40,
  stroke = "var(--red)",
  label,
  className,
}: SparklineProps) {
  const cls = className ? `sparkline ${className}` : "sparkline";
  const box = `0 0 ${width} ${height}`;
  const line = (
    <path
      d={sparklinePath(values, width, height)}
      fill="none"
      stroke={stroke}
      strokeWidth={1.6}
      strokeLinejoin="round"
    />
  );
  if (label) {
    return (
      <svg
        className={cls}
        width={width}
        height={height}
        viewBox={box}
        role="img"
        aria-label={label}
      >
        <title>{label}</title>
        {line}
      </svg>
    );
  }
  return (
    <svg className={cls} width={width} height={height} viewBox={box} aria-hidden="true">
      {line}
    </svg>
  );
}
