import { describe, expect, it } from "vitest";
import { exampleList, examplePage } from "../fixtures/public-example";
import { ApiError, type ApiFetcher } from "./api.server";
import {
  CLIENT_IP_HEADER,
  clientIpFrom,
  getPublicExploitList,
  getPublicExploitPage,
  LIMITS,
  PublicPathError,
  PublicShapeError,
  publicApiUrl,
} from "./public-api.server";

function fakeApi(handler: (url: URL) => Response): ApiFetcher & { calls: URL[] } {
  const calls: URL[] = [];
  return {
    calls,
    fetch: (async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      calls.push(url);
      return handler(url);
    }) as Fetcher["fetch"],
  };
}

describe("publicApiUrl", () => {
  it("accepts paths under /v0/public/", () => {
    expect(publicApiUrl("/v0/public/exploited/a-b").pathname).toBe("/v0/public/exploited/a-b");
  });

  it.each([
    "/v0/radar",
    "/v0/tenants/t_1/attempts",
    "/healthz",
    "v0/public/radar",
    "https://evil.example/v0/public/radar",
    "//evil.example/v0/public/radar",
    "/v0/public/../radar",
    "/v0/public/%2e%2e/admin",
    "/v0/public/..\\admin",
  ])("refuses %s", (path) => {
    expect(() => publicApiUrl(path)).toThrow(PublicPathError);
  });
});

describe("getPublicExploitList", () => {
  it("returns the list from /v0/public/exploited", async () => {
    const api = fakeApi(() => Response.json(exampleList));
    await expect(getPublicExploitList(api)).resolves.toEqual(exampleList);
    expect(api.calls[0].pathname).toBe("/v0/public/exploited");
  });

  it("rejects a body with the wrong shape", async () => {
    const api = fakeApi(() => Response.json({ items: [{ slug: 1 }] }));
    await expect(getPublicExploitList(api)).rejects.toBeInstanceOf(PublicShapeError);
  });

  it("throws ApiError on a server error", async () => {
    const api = fakeApi(() => new Response("down", { status: 503 }));
    await expect(getPublicExploitList(api)).rejects.toBeInstanceOf(ApiError);
  });
});

describe("getPublicExploitPage", () => {
  it("fetches the page by slug", async () => {
    const api = fakeApi(() => Response.json(examplePage));
    await expect(getPublicExploitPage(api, examplePage.slug)).resolves.toEqual(examplePage);
    expect(api.calls[0].pathname).toBe(`/v0/public/exploited/${examplePage.slug}`);
  });

  it("returns null on 404", async () => {
    const api = fakeApi(() =>
      Response.json({ error: { code: "not_found", message: "no" } }, { status: 404 }),
    );
    await expect(getPublicExploitPage(api, "not-published")).resolves.toBeNull();
  });

  it("does not call the API for a slug that cannot exist", async () => {
    const api = fakeApi(() => Response.json(examplePage));
    for (const slug of ["../tenants", "A-B", "a/b", "", "x".repeat(81), "a--b"]) {
      await expect(getPublicExploitPage(api, slug)).resolves.toBeNull();
    }
    expect(api.calls).toHaveLength(0);
  });

  it("rejects a page that is not TLP:CLEAR", async () => {
    const api = fakeApi(() => Response.json({ ...examplePage, tlp: "amber" }));
    await expect(getPublicExploitPage(api, examplePage.slug)).rejects.toBeInstanceOf(
      PublicShapeError,
    );
  });
});

describe("client address forwarding", () => {
  function recordingApi(body: unknown): ApiFetcher & { headers: Headers[] } {
    const headers: Headers[] = [];
    return {
      headers,
      fetch: (async (_input: RequestInfo | URL, init?: RequestInit) => {
        headers.push(new Headers(init?.headers));
        return Response.json(body);
      }) as Fetcher["fetch"],
    };
  }

  it("forwards the client address as X-Foiled-Client-Ip", async () => {
    const api = recordingApi(exampleList);
    await getPublicExploitList(api, { clientIp: "192.0.2.10" });
    expect(CLIENT_IP_HEADER).toBe("X-Foiled-Client-Ip");
    expect(api.headers[0].get("X-Foiled-Client-Ip")).toBe("192.0.2.10");
    const page = recordingApi(examplePage);
    await getPublicExploitPage(page, examplePage.slug, { clientIp: "2001:db8::1" });
    expect(page.headers[0].get("X-Foiled-Client-Ip")).toBe("2001:db8::1");
  });

  it("leaves the header out when there is no address or it is not one", async () => {
    const api = recordingApi(exampleList);
    await getPublicExploitList(api);
    await getPublicExploitList(api, { clientIp: "192.0.2.10\r\nX-Evil: 1" });
    await getPublicExploitList(api, { clientIp: "<script>" });
    for (const h of api.headers) expect(h.has("X-Foiled-Client-Ip")).toBe(false);
  });

  it("reads CF-Connecting-IP from the request", () => {
    const req = (ip?: string) =>
      new Request("https://x/", { headers: ip ? { "CF-Connecting-IP": ip } : {} });
    expect(clientIpFrom(req("203.0.113.7"))).toBe("203.0.113.7");
    expect(clientIpFrom(req())).toBeNull();
    expect(clientIpFrom(req("not an ip"))).toBeNull();
  });
});

describe("bounded data", () => {
  it("reads at most 100 list items", async () => {
    const many = Array.from({ length: 250 }, (_, i) => ({
      ...exampleList.items[0],
      slug: `page-${i}`,
      canonical_path: `/exploited/page-${i}`,
    }));
    const api = fakeApi(() => Response.json({ items: many }));
    const list = await getPublicExploitList(api);
    expect(LIMITS.listItems).toBe(100);
    expect(list.items).toHaveLength(100);
    expect(list.items[99].slug).toBe("page-99");
  });

  it("caps the arrays on a page", async () => {
    const ioc = examplePage.iocs[0];
    const api = fakeApi(() =>
      Response.json({ ...examplePage, iocs: Array.from({ length: 900 }, () => ioc) }),
    );
    const page = await getPublicExploitPage(api, examplePage.slug);
    expect(page?.iocs).toHaveLength(LIMITS.iocs);
  });
});
