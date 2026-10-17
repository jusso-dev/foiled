import { toPrintable, truncateText } from "../lib/printable";

export interface RawRequestBlockProps {
  /** Raw attacker text: request line, headers and body. Rendered as text only. */
  raw: string;
  /** Heading, for example "Raw request". */
  label?: string;
  /** Extra context shown next to the heading, for example a channel or size. */
  meta?: string;
  maxChars?: number;
  maxLines?: number;
}

/**
 * Attacker-supplied request text. Never parsed as HTML: the string goes into
 * a text node (React escapes it), control and bidi characters are shown as
 * escapes, and long payloads are truncated with a clear notice.
 */
export function RawRequestBlock({
  raw,
  label = "Raw request",
  meta,
  maxChars = 2048,
  maxLines = 40,
}: RawRequestBlockProps) {
  const cut = truncateText(raw, maxChars, maxLines);
  return (
    <figure className="card raw">
      <figcaption className="raw__head">
        <span className="panel__title">{label}</span>
        <span className="raw__meta mono">
          {meta ? `${meta} · ` : ""}attacker-supplied, shown as text
        </span>
      </figcaption>
      {/* biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard (WCAG 2.1.1). */}
      <pre className="raw__pre" tabIndex={0}>
        <code>{toPrintable(cut.text)}</code>
      </pre>
      {cut.truncated ? (
        <p className="raw__note">
          Truncated: showing {cut.shownChars.toLocaleString("en-AU")} of{" "}
          {cut.totalChars.toLocaleString("en-AU")} characters ({cut.shownLines} of {cut.totalLines}{" "}
          lines). The full capture stays in quarantine storage.
        </p>
      ) : null}
    </figure>
  );
}
