import { describe, expect, it, vi } from "vitest";
import { exampleList, examplePage } from "../fixtures/public-example";
import { ApiError, type ApiFetcher } from "./api.server";
import {
  BINDING_SECRET_HEADER,
  CLIENT_IP_HEADER,
  clientIpFrom,
  getPublicExploitList,
  getPublicExploitPage,
  LIMITS,
  PublicPathError,
  PublicShapeError,
  publicApiUrl,
  publicRequestOptions,
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

  const bindingSecret = "test-binding-secret-0123456789abcdef-not-real";

  it("forwards the client address with the binding secret", async () => {
    const api = recordingApi(exampleList);
    await getPublicExploitList(api, { clientIp: "192.0.2.10", bindingSecret });
    expect(CLIENT_IP_HEADER).toBe("X-Foiled-Client-Ip");
    expect(BINDING_SECRET_HEADER).toBe("X-Foiled-Binding-Secret");
    expect(api.headers[0].get("X-Foiled-Client-Ip")).toBe("192.0.2.10");
    expect(api.headers[0].get("X-Foiled-Binding-Secret")).toBe(bindingSecret);
    const page = recordingApi(examplePage);
    await getPublicExploitPage(page, examplePage.slug, { clientIp: "2001:db8::1", bindingSecret });
    expect(page.headers[0].get("X-Foiled-Client-Ip")).toBe("2001:db8::1");
    expect(page.headers[0].get("X-Foiled-Binding-Secret")).toBe(bindingSecret);
  });

  it("builds the options from CF-Connecting-IP and PUBLIC_BINDING_SECRET", async () => {
    const request = new Request("https://x/", { headers: { "CF-Connecting-IP": "203.0.113.7" } });
    const options = publicRequestOptions(request, { PUBLIC_BINDING_SECRET: bindingSecret });
    expect(options).toEqual({ clientIp: "203.0.113.7", bindingSecret });
    const api = recordingApi(exampleList);
    await getPublicExploitList(api, options);
    expect(api.headers[0].get("X-Foiled-Client-Ip")).toBe("203.0.113.7");
    expect(api.headers[0].get("X-Foiled-Binding-Secret")).toBe(bindingSecret);
  });

  it("sends neither header without an address or without the secret", async () => {
    const api = recordingApi(exampleList);
    await getPublicExploitList(api);
    await getPublicExploitList(api, { bindingSecret });
    await getPublicExploitList(api, { clientIp: "192.0.2.10" });
    await getPublicExploitList(api, { clientIp: "192.0.2.10", bindingSecret: "" });
    await getPublicExploitList(api, { clientIp: "192.0.2.10\r\nX-Evil: 1", bindingSecret });
    await getPublicExploitList(api, { clientIp: "<script>", bindingSecret });
    expect(api.headers).toHaveLength(6);
    for (const h of api.headers) {
      expect(h.has("X-Foiled-Client-Ip")).toBe(false);
      expect(h.has("X-Foiled-Binding-Secret")).toBe(false);
    }
  });

  it("warns once and omits invalid secrets instead of failing the page", async () => {
    vi.resetModules();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const { getPublicExploitList: read } = await import("./public-api.server");
      const api = recordingApi(exampleList);
      for (const secret of [undefined, "short", `${bindingSecret}\n`, `${bindingSecret}🔒`]) {
        await read(api, { clientIp: "192.0.2.10", bindingSecret: secret });
      }
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0][0]).not.toContain(bindingSecret);
      for (const headers of api.headers) {
        expect(headers.has(CLIENT_IP_HEADER)).toBe(false);
        expect(headers.has(BINDING_SECRET_HEADER)).toBe(false);
      }
    } finally {
      warn.mockRestore();
    }
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
