/**
 * Helpers for showing attacker-controlled text. React escapes markup when we
 * render strings as children; these helpers also make control and bidi
 * characters visible so a payload cannot reorder or hide what an analyst sees.
 */

// C0 controls except tab and newline, DEL, C1 controls, and bidi embedding,
// override and isolate characters (the "Trojan Source" set).
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point.
const UNSAFE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F؜‎‏‪-‮⁦-⁩]/g;

/** Replace control and bidi characters with visible `\xNN` or `\u{NNNN}` escapes. */
export function toPrintable(text: string): string {
  return text.replace(UNSAFE, (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    return cp <= 0xff
      ? `\\x${cp.toString(16).padStart(2, "0")}`
      : `\\u{${cp.toString(16).padStart(4, "0")}}`;
  });
}

export interface Truncated {
  text: string;
  truncated: boolean;
  shownChars: number;
  totalChars: number;
  shownLines: number;
  totalLines: number;
}

/** Cut text to at most `maxChars` characters and `maxLines` lines. */
export function truncateText(text: string, maxChars: number, maxLines: number): Truncated {
  const lines = text.split("\n");
  let out = lines.slice(0, Math.max(0, maxLines)).join("\n");
  if (out.length > maxChars) out = out.slice(0, Math.max(0, maxChars));
  return {
    text: out,
    truncated: out.length < text.length,
    shownChars: out.length,
    totalChars: text.length,
    shownLines: out === "" ? 0 : out.split("\n").length,
    totalLines: lines.length,
  };
}

/** Shorten long single tokens such as hashes in the middle: `abcd…wxyz`. */
export function middleEllipsis(value: string, max = 24): string {
  if (value.length <= max) return value;
  const keep = Math.max(2, Math.floor((max - 1) / 2));
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}
