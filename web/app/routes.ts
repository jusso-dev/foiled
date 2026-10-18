import { index, layout, type RouteConfig, route } from "@react-router/dev/routes";

// Route plan: docs/ui/console.md#routes. Everything inside the console layout
// needs a signed-in operator; /login, /design and the error pages do not.
// The public Worker 404s every console route (app/lib/surface.ts).
export default [
  route("login", "routes/login.tsx"),
  route("logout", "routes/logout.tsx"),
  route("design", "routes/design.tsx"),
  layout("routes/console.tsx", [
    index("routes/overview.tsx"),
    route("search", "routes/search.tsx"),
    route("launch", "routes/launch.tsx"),
    route("decoys", "routes/decoys.tsx"),
    route("decoys/:decoyId", "routes/decoy.tsx"),
    route("attempts", "routes/attempts.tsx"),
    route("attempts/:attemptId", "routes/attempt.tsx"),
    route("review", "routes/review.tsx"),
    route("writeups", "routes/writeups.tsx"),
    route("writeups/:writeupId", "routes/writeup.tsx"),
    route("radar", "routes/radar.tsx"),
    route("actors", "routes/actors.tsx"),
    route("campaigns", "routes/campaigns.tsx"),
    route("campaigns/:campaignId", "routes/campaign.tsx"),
    route("iocs", "routes/iocs.tsx"),
    route("iocs/:iocId", "routes/ioc.tsx"),
    route("exports", "routes/exports.tsx"),
    route("exports/download", "routes/exports.download.tsx"),
    route("quarantine", "routes/quarantine.tsx"),
    route("registry", "routes/registry.tsx"),
    route("audit", "routes/audit.tsx"),
    route("live", "routes/live.tsx"),
  ]),

  // Public exploit pages (#35). Paths must match isPublicPagePath. The radar
  // is trusted-side only and has no public route.
  layout("routes/public/layout.tsx", [
    route("exploited", "routes/public/exploited.tsx"),
    route("exploited/:slug", "routes/public/exploit.tsx"),
  ]),
  route("robots.txt", "routes/public/robots.ts"),
  route("sitemap.xml", "routes/public/sitemap.ts"),
] satisfies RouteConfig;
