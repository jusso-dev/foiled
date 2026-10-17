export type ChangeDirection = "up" | "down" | "flat";

const ARROW: Record<ChangeDirection, string> = { up: "↑", down: "↓", flat: "→" };
const WORD: Record<ChangeDirection, string> = { up: "up", down: "down", flat: "no change" };

/** Trend arrow and percentage. Rising attack counts are red, falling are green. */
export function Change({ direction, pct }: { direction: ChangeDirection; pct: number }) {
  return (
    <span className={`change change--${direction}`}>
      <span aria-hidden="true">
        {ARROW[direction]} {Math.abs(pct)}%
      </span>
      <span className="sr-only">
        {direction === "flat" ? WORD.flat : `${WORD[direction]} ${Math.abs(pct)} per cent`}
      </span>
    </span>
  );
}
