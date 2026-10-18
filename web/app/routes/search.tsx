import { redirect } from "react-router";
import { requireOperator } from "../lib/console.server";
import { searchTarget } from "../lib/navigation";
import type { Route } from "./+types/search";

/** The jump box: send the query to the page that answers it. */
export async function loader(args: Route.LoaderArgs) {
  await requireOperator(args);
  return redirect(searchTarget(new URL(args.request.url).searchParams.get("q")));
}
