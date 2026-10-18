import { Outlet, useLocation } from "react-router";
import { ConsoleShell, CsrfContext } from "../components/console/ConsoleShell";
import { requireOperator } from "../lib/console.server";
import type { Route } from "./+types/console";

/**
 * Layout for every signed-in page. The loader returns who is signed in and
 * the session's CSRF token; the API token itself never leaves the Worker.
 */
export async function loader(args: Route.LoaderArgs) {
  const { session } = await requireOperator(args);
  return {
    operator: { id: session.principal.id, tenant: session.principal.tenant_id },
    scopes: session.principal.scopes,
    csrf: session.csrf,
  };
}

export default function ConsoleLayout({ loaderData }: Route.ComponentProps) {
  const location = useLocation();
  return (
    <CsrfContext.Provider value={loaderData.csrf}>
      <ConsoleShell pathname={location.pathname} operator={loaderData.operator}>
        <Outlet />
      </ConsoleShell>
    </CsrfContext.Provider>
  );
}
