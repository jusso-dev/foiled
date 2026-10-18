import { useId } from "react";
import { data, Form, redirect, useNavigation } from "react-router";
import { Notice } from "../components/console/Notice";
import { FoiledMark } from "../components/icons";
import { cloudflareContext } from "../context";
import { ApiError, ConsoleApi } from "../lib/api.server";
import { readForm } from "../lib/console.server";
import { safeNext } from "../lib/navigation";
import { isRevoked } from "../lib/revocation.server";
import {
  MIN_SECRET_LENGTH,
  newSession,
  openSession,
  readCookie,
  SESSION_COOKIE,
  sameOrigin,
  sealSession,
  sessionCookie,
} from "../lib/session.server";
import type { Route } from "./+types/login";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Sign in · Foiled console" }, { name: "robots", content: "noindex" }];
}

const TOKEN = /^fo_[A-Za-z0-9]{1,64}\.[A-Za-z0-9]{32,256}$/;

export async function loader({ request, context }: Route.LoaderArgs) {
  const { env } = context.get(cloudflareContext);
  const configured = (env.SESSION_SECRET?.length ?? 0) >= MIN_SECRET_LENGTH;
  const next = safeNext(new URL(request.url).searchParams.get("next"));
  if (configured) {
    const raw = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
    const session = await openSession(raw, env.SESSION_SECRET, Date.now()).catch(() => null);
    if (session && !(await isRevoked(env, session).catch(() => true))) throw redirect(next);
  }
  return { configured, next };
}

export async function action({ request, context }: Route.ActionArgs) {
  const { env } = context.get(cloudflareContext);
  // No session exists yet, so there is no CSRF token to check. The origin
  // check stops another site from signing an operator in to its own token.
  if (!sameOrigin(request)) {
    return data({ error: "Cross-site sign-in refused." }, { status: 403 });
  }
  if ((env.SESSION_SECRET?.length ?? 0) < MIN_SECRET_LENGTH) {
    return data({ error: "The console has no session secret configured." }, { status: 503 });
  }
  const form = await readForm(request, 4096);
  const token = String(form.get("token") ?? "").trim();
  const next = safeNext(String(form.get("next") ?? "/"));
  if (!TOKEN.test(token)) {
    return data({ error: "That is not an operator token (fo_<id>.<secret>)." }, { status: 400 });
  }
  let principal: Awaited<ReturnType<ConsoleApi["whoami"]>>;
  try {
    principal = await new ConsoleApi(env.API, token).whoami();
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      return data({ error: "The API did not accept that token." }, { status: 401 });
    }
    return data({ error: "The API could not be reached. Try again." }, { status: 502 });
  }
  if (principal.role !== "human") {
    return data(
      { error: "Only operator tokens can sign in. MCP, host and sensor credentials cannot." },
      { status: 403 },
    );
  }
  const now = Date.now();
  const session = newSession(token, principal, now);
  const sealed = await sealSession(session, env.SESSION_SECRET);
  return redirect(next, {
    headers: { "set-cookie": sessionCookie(sealed, session.exp - now) },
  });
}

export default function Login({ loaderData, actionData }: Route.ComponentProps) {
  const id = useId();
  const navigation = useNavigation();
  const busy = navigation.state === "submitting";
  return (
    <main className="login">
      <section className="card login__card" aria-labelledby={`${id}-title`}>
        <div className="brand">
          <FoiledMark />
          <div>
            <div className="brand__wordmark">FOILED</div>
            <div className="brand__tag">Operator console</div>
          </div>
        </div>
        <h1 id={`${id}-title`} className="login__title">
          Sign in
        </h1>
        {!loaderData.configured ? (
          <Notice kind="error" title="Sign-in is not configured">
            <p>
              Set the <code>SESSION_SECRET</code> Worker secret (at least 32 characters) on the
              console Worker. See docs/ui/console.md.
            </p>
          </Notice>
        ) : null}
        {actionData?.error ? (
          <Notice kind="error">
            <p>{actionData.error}</p>
          </Notice>
        ) : null}
        <Form method="post" className="login__form">
          <input type="hidden" name="next" value={loaderData.next} />
          <div className="field field--wide">
            <label htmlFor={`${id}-token`}>Operator API token</label>
            <input
              id={`${id}-token`}
              name="token"
              type="password"
              required
              autoComplete="off"
              spellCheck={false}
              maxLength={330}
              aria-describedby={`${id}-hint`}
            />
            <p id={`${id}-hint`} className="hint">
              A bearer token of the form fo_&lt;id&gt;.&lt;secret&gt; with operator scopes. The
              console checks it with the API and keeps it only in an encrypted, httpOnly cookie. It
              is never stored in the browser's storage or sent to page scripts.
            </p>
          </div>
          <button
            type="submit"
            className="btn btn--primary"
            disabled={busy || !loaderData.configured}
          >
            {busy ? "Checking..." : "Sign in"}
          </button>
        </Form>
      </section>
    </main>
  );
}
