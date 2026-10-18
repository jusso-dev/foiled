# ADR 0011: Public pages on the web Worker

## Status

Proposed (18 Oct 2026). Issue #35. Related: [ADR 0009](0009-axum-workers-and-front-end.md) (front end), [ADR 0001](0001-architecture.md), #39 (design system), #14 (console), [research-writeups.md](../research-writeups.md).

## Context

ADR 0009 chose React Router on Workers for the console (`web/`) and Astro on Workers for the public exploit pages and write-ups (`site/`), so public traffic and SEO concerns stay away from the trusted console.

When #35 was built, the design system (#39) existed only as React components in `web/app/components`, with tests for escaping (`toPrintable`), contrast and the confidence wording. An Astro site would need those components rebuilt or a React integration added, a second set of front-end dependencies, and its own copy of the escaping and wording rules. The public pages are small: a list, a page and the radar, all server-rendered from three read-only API routes.

## Decision

Build the public pages as routes in `web/` and deploy the same build twice:

- `foiled-web` with `FOILED_SURFACE=console`: the console, behind Cloudflare Access. It can also show the public routes.
- `foiled-public` with `FOILED_SURFACE=public` (`env.public` in `web/wrangler.jsonc`, built with `CLOUDFLARE_ENV=public`): no Access policy, and a surface guard in `workers/app.ts` that serves only the public paths, their data requests and built assets, and returns 404 for everything else. Any value other than `console` is treated as public, so a misconfiguration fails closed.

The keep-public-traffic-apart goal of ADR 0009 is met by the separate Worker, hostname and guard rather than a separate framework. The public loaders use a client that only allows API paths under `/v0/public/`, and those API routes read only allow-listed page snapshots (`crates/api/src/routes/public.rs`). The public Worker also rate limits each client (a Workers Rate Limiting binding) and blocks React Router's `/__manifest`.

This supersedes the public-site location in ADR 0009 (option B, `site/`); the rest of ADR 0009 stands.

### No public radar

The radar stays trusted-side only, as #35 specifies: operators see it through `GET /v0/radar` and the console (#14). An earlier draft of #35 also served aggregated counts on a public `/radar` page; it was removed in review. Even behind minimum counts and a delay, public aggregates of customer-adjacent data add risk (differencing, timing) for little gain over the write-ups, which carry the reviewed, citable findings. The public site serves only published exploit pages, `robots.txt` and `sitemap.xml`.

## Consequences

- One design system, one escaping helper and one set of wording rules for the console and the public pages.
- No new framework or packages.
- The console's code ships in the public Worker bundle even though the guard never serves it. The route list is public in this repository anyway. Data for console routes needs credentials the public Worker never has.
- A guard bug could expose console routes on the public hostname, so the guard is a small pure module with tests, and the API still demands credentials for every non-public route.
- If the public site grows into a Markdown-heavy content site, Astro (ADR 0009 option B) is still open; the API contract would not change.
- Public pages are cached for 60 seconds and purged on withdrawal ([research-writeups.md](../research-writeups.md#caching-and-withdrawal)).

## Alternatives considered

- **Astro in `site/` as ADR 0009 planned.** Better for a large static content site, but it duplicates the design system and safety helpers for three pages, and adds dependencies. Deferred, not rejected.
- **Public routes in the console Worker only, with an Access bypass for some paths.** One deployment, but public traffic and console traffic share a Worker and a hostname, and a mistake in the Access path rules exposes the console. Rejected.
- **Static export at publish time.** No Worker at all for public pages, but the delayed IOC release changes a page after publish, so pages would need rebuilding on a schedule. Rejected for now.
