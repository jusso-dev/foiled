import type { ReactNode } from "react";
import { toPrintable } from "../../lib/printable";

export interface LoadErrorLike {
  status: number;
  message: string;
  notServed: boolean;
}

/** A short status line: empty results, information, success or failure. */
export function Notice({
  kind,
  title,
  children,
}: {
  kind: "info" | "empty" | "ok" | "error" | "warn";
  title?: string;
  children?: ReactNode;
}) {
  // Errors and successes after a form post are announced; empty and info states are not.
  const role = kind === "error" ? "alert" : kind === "ok" ? "status" : undefined;
  return (
    <div className={`notice notice--${kind}`} role={role}>
      {title ? <p className="notice__title">{title}</p> : null}
      {children ? <div className="notice__body">{children}</div> : null}
    </div>
  );
}

/** Nothing to show yet. Says what would make something appear. */
export function EmptyState({ children }: { children: ReactNode }) {
  return <Notice kind="empty">{children}</Notice>;
}

/**
 * A failed API read, in place of the panel it was for. A planned route that
 * the API does not serve yet says so and names the issue that will ship it.
 */
export function ErrorState({
  error,
  what,
  issue,
}: {
  error: LoadErrorLike;
  what: string;
  issue?: number;
}) {
  if (error.notServed) {
    return (
      <Notice kind="warn" title={`${what}: not served yet`}>
        <p>
          The API does not serve this yet
          {issue ? (
            <>
              {" "}
              (planned in{" "}
              <a className="link" href={`https://github.com/jusso-dev/foiled/issues/${issue}`}>
                #{issue}
              </a>
              )
            </>
          ) : null}
          . This view will fill in once it does.
        </p>
      </Notice>
    );
  }
  return (
    <Notice kind="error" title={`Could not load ${what.toLowerCase()}`}>
      <p>{toPrintable(error.message)}</p>
    </Notice>
  );
}

/** Result of a form post, shown next to the form that sent it. */
export function ActionNotice({ result }: { result?: { ok: boolean; message: string } | null }) {
  if (!result) return null;
  return (
    <Notice kind={result.ok ? "ok" : "error"}>
      <p>{toPrintable(result.message)}</p>
    </Notice>
  );
}
