import { redirect } from "react-router";
import { requireMutation } from "../lib/console.server";
import { revokeSession } from "../lib/revocation.server";
import { clearSessionCookie } from "../lib/session.server";
import type { Route } from "./+types/logout";

export function loader() {
  return redirect("/");
}

/** Sign out: a CSRF-checked POST that clears the session cookie. */
export async function action(args: Route.ActionArgs) {
  const { env, session } = await requireMutation(args);
  // Revoke server-side first, so a copied cookie stops working now, not at expiry.
  await revokeSession(env, session);
  return redirect("/login", { headers: { "set-cookie": clearSessionCookie() } });
}
