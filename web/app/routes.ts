import { index, layout, type RouteConfig, route } from "@react-router/dev/routes";

export default [
  // Console routes. The public Worker 404s these (app/lib/surface.ts).
  index("routes/home.tsx"),
  route("design", "routes/design.tsx"),

  // Public exploit pages (#35). Paths must match isPublicPagePath. The radar
  // is trusted-side only and has no public route.
  layout("routes/public/layout.tsx", [
    route("exploited", "routes/public/exploited.tsx"),
    route("exploited/:slug", "routes/public/exploit.tsx"),
  ]),
  route("robots.txt", "routes/public/robots.ts"),
  route("sitemap.xml", "routes/public/sitemap.ts"),
] satisfies RouteConfig;
