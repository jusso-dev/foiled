import { isRouteErrorResponse, Link, useRouteError } from "react-router";
import { toPrintable } from "../../lib/printable";
import { PageHead } from "./Controls";
import { ErrorState } from "./Notice";

/**
 * Error boundary for console pages. Renders inside the console shell, so the
 * operator keeps the navigation. Loader errors carry a LoadError body.
 */
export function RouteError({ what }: { what: string }) {
  const error = useRouteError();
  if (isRouteErrorResponse(error)) {
    const body = (error.data ?? {}) as { message?: unknown; notServed?: unknown };
    const message =
      typeof body.message === "string"
        ? body.message
        : error.status === 404
          ? "Not found, or not visible to your tenant."
          : `Error ${error.status}.`;
    return (
      <>
        <PageHead title={what} />
        <ErrorState
          what={what}
          error={{
            status: error.status,
            message: toPrintable(message),
            notServed: body.notServed === true,
          }}
        />
        <p>
          <Link className="link" to="/">
            Back to the overview
          </Link>
        </p>
      </>
    );
  }
  return (
    <>
      <PageHead title={what} />
      <ErrorState
        what={what}
        error={{ status: 500, message: "Something went wrong in the console.", notServed: false }}
      />
    </>
  );
}
