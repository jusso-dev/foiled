import { publicWordingSentence } from "../lib/confidence";

export interface WordingChipProps {
  /** Wording from the public API. Only the exact value "confirmed" shows as Confirmed. */
  wording: unknown;
  /** Completes the sentence "We assess as ...", for example "an attempt against CVE-2099-0001". */
  what?: string;
}

/**
 * Public pages have no scores, only the wording. `WE ASSESS AS` (amber) or
 * `CONFIRMED` (green), with the full sentence for tooltips and screen readers.
 */
export function WordingChip({ wording, what }: WordingChipProps) {
  const confirmed = wording === "confirmed";
  const level = confirmed ? "confirmed" : "assessed";
  const sentence = publicWordingSentence(wording, what);
  return (
    <span className={`chip chip--${level}`} title={sentence} data-confidence={level}>
      <span className="sr-only">{sentence}</span>
      <span aria-hidden="true">{confirmed ? "Confirmed" : "We assess as"}</span>
    </span>
  );
}
