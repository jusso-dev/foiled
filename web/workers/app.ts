import { createRequestHandler, RouterContextProvider } from "react-router";
import { cloudflareContext } from "../app/context";
import {
  publicNotFound,
  publicRateLimited,
  publicRedirect,
  withConsoleHeaders,
  withPublicDefaults,
} from "../app/lib/http-headers";
import { isRateLimited, rateLimitKey } from "../app/lib/rate-limit";
import { isPublicPath, publicDecision, surfaceFrom } from "../app/lib/surface";

const requestHandler = createRequestHandler(
  () => import("virtual:react-router/server-build"),
  import.meta.env.MODE,
);

export default {
  async fetch(request, env, ctx) {
    const { pathname, search } = new URL(request.url);

    // The public Worker has no Cloudflare Access policy in front of it, so it
    // serves only the public allow-list (app/lib/surface.ts). The console
    // Worker stays behind Access and serves everything.
    if (surfaceFrom(env.FOILED_SURFACE) === "public") {
      const decision = publicDecision(pathname, search);
      if (decision.action === "not-found") return publicNotFound();
      // Per-client limit on anything that renders or calls the API. The
      // binding only exists on the public Worker (wrangler.jsonc env.public).
      if (await isRateLimited(env.PUBLIC_RATE_LIMIT, rateLimitKey(request))) {
        return publicRateLimited();
      }
      if (decision.action === "redirect") return publicRedirect(decision.location);
    }

    const context = new RouterContextProvider();
    context.set(cloudflareContext, { env, ctx });
    const response = await requestHandler(request, context);
    return isPublicPath(pathname) ? withPublicDefaults(response) : withConsoleHeaders(response);
  },
} satisfies ExportedHandler<Env>;
