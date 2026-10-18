import { describe, expect, it } from "vitest";
import {
  ApiError,
  type ApiFetcher,
  apiJson,
  BadIdError,
  ConsoleApi,
  getHealth,
} from "./api.server";

function fakeApi(handler: (url: string) => Response): ApiFetcher & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: (async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      return handler(url);
    }) as Fetcher["fetch"],
  };
}

describe("getHealth", () => {
  it("returns the API health body", async () => {
    const api = fakeApi(() =>
      Response.json({ status: "ok", service: "foiled-api", version: "0.1.0" }),
    );
    await expect(getHealth(api)).resolves.toEqual({
      status: "ok",
      service: "foiled-api",
      version: "0.1.0",
    });
    expect(new URL(api.calls[0]).pathname).toBe("/healthz");
  });

  it("returns null when the API errors", async () => {
    const api = fakeApi(() => new Response("down", { status: 503 }));
    await expect(getHealth(api)).resolves.toBeNull();
  });

  it("returns null when the body has the wrong shape", async () => {
    const api = fakeApi(() => Response.json({ status: 1 }));
    await expect(getHealth(api)).resolves.toBeNull();
  });
});

describe("apiJson", () => {
  it("throws ApiError with the status on non-2xx", async () => {
    const api = fakeApi(() => new Response(null, { status: 404 }));
    await expect(apiJson(api, "/v0/missing")).rejects.toMatchObject(
      new ApiError("/v0/missing", 404),
    );
  });
});

describe("ConsoleApi", () => {
  const TOKEN = `fo_tok1.${"c".repeat(40)}`;

  function recorder(res: () => Response = () => Response.json({ items: [] })) {
    const calls: { url: URL; init: RequestInit }[] = [];
    const api: ApiFetcher = {
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        calls.push({ url: new URL(String(input)), init: init ?? {} });
        return res();
      }) as Fetcher["fetch"],
    };
    return { calls, client: new ConsoleApi(api, TOKEN) };
  }

  it("sends the bearer token and never a tenant id", async () => {
    const { calls, client } = recorder();
    await client.listAttempts({ state: "exploit", src: "", min_confidence: undefined });
    const h = new Headers(calls[0].init.headers);
    expect(h.get("authorization")).toBe(`Bearer ${TOKEN}`);
    expect(calls[0].url.pathname).toBe("/v0/attempts");
    expect([...calls[0].url.searchParams.keys()]).toEqual(["state"]);
    expect(calls[0].url.search).not.toContain("tenant");
  });

  it("sends JSON bodies and idempotency keys on writes", async () => {
    const { calls, client } = recorder(() =>
      Response.json({ decoy: {}, job_id: "j", job_kind: "decoy.create" }, { status: 201 }),
    );
    await client.createDecoy({ catalogue_id: "foiled/demo-app/1.0.0" }, "key-1");
    const h = new Headers(calls[0].init.headers);
    expect(calls[0].init.method).toBe("POST");
    expect(h.get("idempotency-key")).toBe("key-1");
    expect(h.get("content-type")).toBe("application/json");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({
      catalogue_id: "foiled/demo-app/1.0.0",
    });
  });

  it("keeps catalogue slashes but escapes and checks every other id", async () => {
    const { calls, client } = recorder(() => Response.json({}));
    await client.getCatalogueEntry("emulator/redis/7.0");
    expect(calls[0].url.pathname).toBe("/v0/catalogue/entries/emulator/redis/7.0");
    await client.decoyAction("dcy-1", "destroy", { code: "operator_manual", text: "t" }, "k");
    expect(calls[1].url.pathname).toBe("/v0/decoys/dcy-1:destroy");
    for (const bad of ["../audit", "a/b", "..", "x?y=1", ""]) {
      await expect(client.getDecoy(bad)).rejects.toBeInstanceOf(BadIdError);
    }
    await expect(client.getAttempt("att_123")).rejects.toBeInstanceOf(BadIdError);
    await expect(client.getCatalogueEntry("../../v0/audit")).rejects.toBeInstanceOf(BadIdError);
    expect(calls).toHaveLength(2);
  });

  it("carries the API's error code and message, and spots unserved routes", async () => {
    const { client } = recorder(() =>
      Response.json({ error: { code: "not_found", message: "route not found" } }, { status: 404 }),
    );
    const err = await client.listReview().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 404, code: "not_found", detail: "route not found" });
    expect(err.notServed).toBe(true);
    const other = recorder(() =>
      Response.json({ error: { code: "not_found", message: "decoy not found" } }, { status: 404 }),
    );
    expect((await other.client.getDecoy("dcy-1").catch((e) => e)).notServed).toBe(false);
  });
});
