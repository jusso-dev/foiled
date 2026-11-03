// Console settings that are not in wrangler.jsonc. Set them with
// `wrangler secret put` or in `.dev.vars` for local development
// (docs/ui/console.md). Merged into the generated `Env`.
interface Env {
  /** At least 32 characters. Encrypts the session cookie. Sign-in is refused without it. */
  SESSION_SECRET?: string;
  /** `on` shows quarantine download controls. Absent or anything else means off. */
  QUARANTINE_DOWNLOADS?: string;
  /**
   * `development` lets the console run without Cloudflare Access, for local
   * work only. Anything else (or unset) requires ACCESS_TEAM_DOMAIN and ACCESS_AUD.
   */
  CONSOLE_ENV?: string;
  /** Cloudflare Access team domain. With ACCESS_AUD, every request needs a valid Access token. */
  ACCESS_TEAM_DOMAIN?: string;
  /** Cloudflare Access application audience tag. */
  ACCESS_AUD?: string;
  /**
   * Public site only. The same value as the API Worker's secret of that name,
   * at least 32 characters. Lets the API rate limit public reads per visitor;
   * without it every visitor shares one API bucket (docs/deploy/workers.md).
   */
  PUBLIC_BINDING_SECRET?: string;
}
