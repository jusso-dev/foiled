import { describe, expect, it } from "vitest";
import { isRateLimited, type RateLimiter, rateLimitKey } from "./rate-limit";

function limiter(allow: number): RateLimiter & { keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    limit: async ({ key }) => {
      keys.push(key);
      return { success: keys.filter((k) => k === key).length <= allow };
    },
  };
}

const req = (headers: Record<string, string> = {}) => new Request("https://x/", { headers });

describe("rateLimitKey", () => {
  it("uses CF-Connecting-IP, or one shared bucket when it is missing", () => {
    expect(rateLimitKey(req({ "CF-Connecting-IP": "198.51.100.4" }))).toBe("198.51.100.4");
    expect(rateLimitKey(req())).toBe("unknown");
    expect(rateLimitKey(req({ "CF-Connecting-IP": "x y" }))).toBe("unknown");
  });
});

describe("isRateLimited", () => {
  it("does not limit when there is no binding (console, tests)", async () => {
    await expect(isRateLimited(undefined, "198.51.100.4")).resolves.toBe(false);
  });

  it("limits a key once the binding says it is over", async () => {
    const l = limiter(2);
    expect(await isRateLimited(l, "198.51.100.4")).toBe(false);
    expect(await isRateLimited(l, "198.51.100.4")).toBe(false);
    expect(await isRateLimited(l, "198.51.100.4")).toBe(true);
    expect(await isRateLimited(l, "203.0.113.9")).toBe(false);
    expect(l.keys).toEqual(["198.51.100.4", "198.51.100.4", "198.51.100.4", "203.0.113.9"]);
  });

  it("lets the request through when the binding fails", async () => {
    const broken: RateLimiter = {
      limit: async () => {
        throw new Error("binding down");
      },
    };
    await expect(isRateLimited(broken, "198.51.100.4")).resolves.toBe(false);
  });
});
