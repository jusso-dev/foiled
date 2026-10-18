import { isRouteErrorResponse, Outlet } from "react-router";
import { PublicShell } from "../../components/PublicShell";
import type { Route } from "./+types/layout";

/** Used only when a child route fails: error pages are never indexed. */
export function meta(_: Route.MetaArgs) {
  return [{ title: "Not available · Foiled" }, { name: "robots", content: "noindex" }];
}

/** Public site frame (#35). Children are the exploit list and exploit pages. */
export default function PublicLayout() {
  return (
    <PublicShell active="exploited">
      <Outlet />
    </PublicShell>
  );
}

/**
 * A failed API call keeps the public frame and says so plainly. The Worker
 * marks the response no-store, so an outage is never cached.
 */
export function ErrorBoundary({ error }: Route.ErrorBoundaryProps) {
  const notFound = isRouteErrorResponse(error) && error.status === 404;
  return (
    <PublicShell active="exploited">
      <h1 className="pub-title">{notFound ? "Not found" : "Not available right now"}</h1>
      <p className="pub-lead">
        {notFound
          ? "That page does not exist or is not published."
          : "We could not load this page. Try again in a few minutes."}
      </p>
    </PublicShell>
  );
}
