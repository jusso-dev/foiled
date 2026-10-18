import { describe, expect, it } from "vitest";
import { SESSION_COOKIE } from "../lib/session.server";
import {
  ADMIN,
  apiError,
  envWith,
  expectPage,
  expectRedirect,
  fakeApi,
  page,
  signIn,
  TOKEN,
  text,
} from "../test/harness";

const whoami = (principal = ADMIN) =>
  fakeApi((c) =>
    c.path === "/v0/whoami" ? principal : { items: [], truncated: false, notes: [] },
  );

describe("sign in", () => {
  it("sends a signed-out operator to /login with the page to come back to", async () => {
    const env = envWith(whoami());
    const to = expectRedirect(await page(env, "/attempts?state=exploit"));
    expect(to).toBe("/login?next=%2Fattempts%3Fstate%3Dexploit");
  });

  it("checks the token with the API and sets an encrypted, httpOnly session cookie", async () => {
    const api = whoami();
    const r = await page(envWith(api), "/login", { form: { token: TOKEN, next: "/attempts" } });
    expect(r.kind).toBe("response");
    if (r.kind !== "response") return;
    expect(r.response.headers.get("location")).toBe("/attempts");
    const cookie = r.response.headers.get("set-cookie") ?? "";
    expect(cookie.startsWith(`${SESSION_COOKIE}=`)).toBe(true);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/");
    // The token never appears in the cookie in the clear.
    expect(cookie).not.toContain(TOKEN);
    expect(cookie).not.toContain("tok1");
    expect(api.calls[0].path).toBe("/v0/whoami");
    expect(api.calls[0].headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
  });

  it("refuses MCP, host and sensor credentials", async () => {
    const api = whoami({ ...ADMIN, role: "mcp" });
    const r = expectPage(await page(envWith(api), "/login", { form: { token: TOKEN } }));
    expect(r.status).toBe(403);
    expect(text(r.html)).toContain("Only operator tokens can sign in");
  });

  it("says when the API rejects the token", async () => {
    const api = fakeApi(() => apiError(401, "unauthorised", "invalid credentials"));
    const r = expectPage(await page(envWith(api), "/login", { form: { token: TOKEN } }));
    expect(r.status).toBe(401);
    expect(text(r.html)).toContain("The API did not accept that token");
  });

  it("rejects malformed tokens before calling the API", async () => {
    const api = whoami();
    const r = expectPage(await page(envWith(api), "/login", { form: { token: "fo_x.short" } }));
    expect(r.status).toBe(400);
    expect(api.calls).toHaveLength(0);
  });

  it("refuses a cross-site sign-in post", async () => {
    const api = whoami();
    const r = expectPage(
      await page(envWith(api), "/login", {
        form: { token: TOKEN },
        origin: "https://evil.example",
      }),
    );
    expect(r.status).toBe(403);
    expect(api.calls).toHaveLength(0);
  });

  it("never redirects off-site after sign-in", async () => {
    const r = await page(envWith(whoami()), "/login", {
      form: { token: TOKEN, next: "//evil.example/x" },
    });
    expect(expectRedirect(r)).toBe("/");
  });

  it("refuses to sign in without a session secret", async () => {
    const env = envWith(whoami(), { SESSION_SECRET: undefined });
    const r = expectPage(await page(env, "/login"));
    expect(text(r.html)).toContain("Sign-in is not configured");
    const post = expectPage(await page(env, "/login", { form: { token: TOKEN } }));
    expect(post.status).toBe(503);
  });

  it("does not put the token in the page", async () => {
    const { cookie } = await signIn();
    const api = fakeApi(() => ({ items: [], truncated: false, notes: [] }));
    const r = expectPage(await page(envWith(api), "/attempts", { cookie }));
    expect(r.html).not.toContain(TOKEN);
    expect(JSON.stringify(r.loaderData)).not.toContain(TOKEN);
    expect(text(r.html)).toContain("Signed in as tok1 tenant t1");
  });

  it("ends the session when the API says the token is no longer valid", async () => {
    const { cookie } = await signIn();
    const api = fakeApi(() => apiError(401, "unauthorised", "invalid credentials"));
    const r = await page(envWith(api), "/attempts", { cookie });
    expect(expectRedirect(r)).toBe("/login?next=%2Fattempts");
    if (r.kind === "response") expect(r.response.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("ignores a session sealed with another secret", async () => {
    const { cookie } = await signIn();
    const env = envWith(whoami(), { SESSION_SECRET: "another-secret-another-secret-12345" });
    const r = await page(env, "/", { cookie });
    expect(expectRedirect(r)).toBe("/login");
    if (r.kind === "response") expect(r.response.headers.get("set-cookie")).toContain("Max-Age=0");
  });
});

describe("sign out and CSRF", () => {
  it("signs out with a CSRF-checked post that clears the cookie", async () => {
    const { cookie, session } = await signIn();
    const r = await page(envWith(whoami()), "/logout", { cookie, form: { csrf: session.csrf } });
    expect(expectRedirect(r)).toBe("/login");
    if (r.kind === "response") expect(r.response.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("refuses a post without the session's CSRF token", async () => {
    const { cookie } = await signIn();
    const r = expectPage(
      await page(envWith(whoami()), "/logout", { cookie, form: { csrf: "nope" } }),
    );
    expect(r.status).toBe(403);
  });

  it("refuses a post from another origin even with the token", async () => {
    const { cookie, session } = await signIn();
    const r = expectPage(
      await page(envWith(whoami()), "/logout", {
        cookie,
        form: { csrf: session.csrf },
        origin: "https://evil.example",
      }),
    );
    expect(r.status).toBe(403);
  });

  it("puts the CSRF token in every console form", async () => {
    const { cookie, session } = await signIn();
    const r = expectPage(await page(envWith(whoami()), "/attempts", { cookie }));
    expect(r.html).toContain(`name="csrf" value="${session.csrf}"`);
  });
});
