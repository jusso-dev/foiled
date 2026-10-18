import { cloudflareContext } from "../../context";
import { NOT_FOUND_CACHE, PUBLIC_CACHE, publicHeaders } from "../../lib/http-headers";
import { clientIpFrom, getPublicExploitList } from "../../lib/public-api.server";
import type { PublicExploitListItem } from "../../lib/public-types";
import { sitemapXml } from "../../lib/seo";
import type { Route } from "./+types/sitemap";

export async function loader({ request, context }: Route.LoaderArgs) {
  const { env } = context.get(cloudflareContext);
  const origin = new URL(request.url).origin;
  // If the list is unavailable, still list the fixed pages, but cache briefly.
  let items: readonly PublicExploitListItem[] = [];
  let cache = PUBLIC_CACHE;
  try {
    items = (await getPublicExploitList(env.API, { clientIp: clientIpFrom(request) })).items;
  } catch {
    cache = NOT_FOUND_CACHE;
  }
  const h = publicHeaders(cache);
  h.set("Content-Type", "application/xml; charset=utf-8");
  return new Response(sitemapXml(origin, items), { headers: h });
}
