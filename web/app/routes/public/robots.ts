import { PUBLIC_CACHE, publicHeaders } from "../../lib/http-headers";
import { robotsTxt } from "../../lib/seo";
import type { Route } from "./+types/robots";

export function loader({ request }: Route.LoaderArgs) {
  const h = publicHeaders(PUBLIC_CACHE);
  h.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(robotsTxt(new URL(request.url).origin), { headers: h });
}
