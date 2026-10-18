import { redirect } from "react-router";
import { requireMutation } from "../lib/console.server";
import { clearSessionCookie } from "../lib/session.server";
import type { Route } from "./+types/logout";

export function loader() {
  return redirect("/");
}

/** Sign out: a CSRF-checked POST that clears the session cookie. */
export async function action(args: Route.ActionArgs) {
  await requireMutation(args);
  return redirect("/login", { headers: { "set-cookie": clearSessionCookie() } });
}
