import { describe, expect, it } from "vitest";
import { ApiError, type ApiFetcher, apiJson, getHealth } from "./api.server";

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
