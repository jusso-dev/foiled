import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { exampleList, examplePage } from "../fixtures/public-example";
import type { BlockNode, PublicExploitPage } from "../lib/public-types";
import Exploit from "../routes/public/exploit";
import Exploited from "../routes/public/exploited";
import { ArticleBody, withPaths } from "./ArticleBody";
import { CveRef } from "./CveRef";
import { PublicShell } from "./PublicShell";

const html = (el: React.ReactElement) => renderToStaticMarkup(el);

/** Route components only read `loaderData` here; the rest of the props are not used. */
function props<C extends (p: never) => unknown>(_c: C, loaderData: unknown): Parameters<C>[0] {
  return { loaderData } as unknown as Parameters<C>[0];
}

const para = (...inlines: unknown[]) => ({ type: "paragraph", inlines }) as BlockNode;

describe("withPaths", () => {
  it("keys nodes by their path in the tree", () => {
    expect(withPaths(["a", "b"], "b").map((n) => n.path)).toEqual(["b0", "b1"]);
    expect(withPaths(["x"], "b1.l0.i").map((n) => n.path)).toEqual(["b1.l0.i0"]);
    expect(withPaths("not a list", "b")).toEqual([]);
  });
});

describe("ArticleBody", () => {
  it("renders the block tree with headings mapped to h2 to h4", () => {
    const out = html(<ArticleBody blocks={examplePage.body} />);
    expect(out).toContain('<h2 class="article__h">What we saw</h2>');
    expect(out).toContain('<h3 class="article__h">Detection</h3>');
    expect(out).not.toContain("<h1");
    expect(out).toContain("<strong>several sources</strong>");
    expect(out).toContain("<ul><li>");
    expect(out).toContain("<blockquote>");
    expect(out).toContain("<hr/>");
    expect(out).toContain('<a href="/exploited">exploit list</a>');
    expect(out).toContain(
      '<a href="https://example.com/advisory" rel="nofollow noopener noreferrer ugc">example advisory</a>',
    );
  });

  it("never lets a heading become h1 or h5", () => {
    const out = html(
      <ArticleBody
        blocks={[
          { type: "heading", level: 1, inlines: [{ type: "text", text: "one" }] },
          { type: "heading", level: 6, inlines: [{ type: "text", text: "six" }] },
        ]}
      />,
    );
    expect(out).not.toMatch(/<h[1156]/);
    expect(out.match(/<h2/g)).toHaveLength(2);
  });

  it("escapes hostile text instead of rendering markup", () => {
    const hostile = [
      "<script>alert(1)</script>",
      '<img src=x onerror="alert(1)">',
      "<a href=javascript:alert(1)>x</a>",
    ];
    const out = html(
      <ArticleBody
        blocks={[
          { type: "heading", level: 2, inlines: [{ type: "text", text: hostile[0] }] },
          para(
            { type: "text", text: hostile[1] },
            { type: "strong", text: hostile[2] },
            { type: "code", text: hostile[0] },
          ),
          { type: "code", text: hostile.join("\n") },
          { type: "list", ordered: true, items: [[{ type: "emphasis", text: hostile[1] }]] },
        ]}
      />,
    );
    expect(out).not.toContain("<script");
    expect(out).not.toContain("<img");
    expect(out).not.toMatch(/<a /);
    expect(out).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(out).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  });

  it("shows bidi and control characters as visible escapes", () => {
    const out = html(
      <ArticleBody
        blocks={[
          para({ type: "text", text: "abc‮def" }),
          { type: "code", text: "x\u001b[31my" },
          para({ type: "link", text: "evil‮txt.exe", href: "/exploited" }),
        ]}
      />,
    );
    expect(out).toContain("abc\\u{202e}def");
    expect(out).toContain("x\\x1b[31my");
    expect(out).toContain("evil\\u{202e}txt.exe");
    expect(out).not.toContain("‮");
    expect(out).not.toContain("\u001b");
  });

  it.each([
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "//evil.example/x",
    "/\\evil.example/x",
    "http://example.com/",
    "vbscript:x",
  ])("drops the unsafe href %s but keeps the words", (href) => {
    const out = html(<ArticleBody blocks={[para({ type: "link", text: "click", href })]} />);
    expect(out).toBe('<div class="article"><p>click</p></div>');
  });

  it("ignores block and inline types it does not know", () => {
    const out = html(
      <ArticleBody
        blocks={[
          { type: "html", html: "<script>alert(1)</script>" } as unknown as BlockNode,
          para({ type: "raw", text: "<b>x</b>" }, { type: "text", text: "ok" }),
        ]}
      />,
    );
    expect(out).toBe('<div class="article"><p>ok</p></div>');
  });
});

describe("CveRef with public wording", () => {
  it("says we assess as for an unconfirmed CVE", () => {
    const out = html(<CveRef id="CVE-2099-0001" wording="we assess as" />);
    expect(out).toContain("chip--assessed");
    expect(out).toContain("We assess as an attempt against CVE-2099-0001");
    expect(out).toContain("Not confirmed by an analyst");
    expect(out).not.toMatch(/>Confirmed</);
  });

  it("says confirmed only when the API wording is confirmed", () => {
    const out = html(<CveRef id="CVE-2099-0001" wording="confirmed" />);
    expect(out).toContain("chip--confirmed");
    expect(out).toContain(">Confirmed<");
    expect(out).toContain("Confirmed by an analyst as an attempt against CVE-2099-0001");
  });

  it("treats any other wording as we assess as", () => {
    const out = html(<CveRef id="CVE-2099-0001" wording={"Confirmed" as "confirmed"} />);
    expect(out).toContain("chip--assessed");
    expect(out).not.toContain("chip--confirmed");
  });
});

describe("PublicShell", () => {
  it("has the wordmark, the exploit list link and the wording note", () => {
    const out = html(
      <PublicShell active="exploited">
        <p>child</p>
      </PublicShell>,
    );
    expect(out).toContain('href="/exploited"');
    expect(out).toContain('href="/exploited" class="pub__link pub__link--on" aria-current="page"');
    expect(out).not.toContain("/radar");
    expect(out).toContain("FOILED");
    expect(out).toContain("We assess as");
    expect(out).toContain("<main");
  });
});

describe("exploit list page", () => {
  it("lists titles, summaries, dates and CVEs with their wording", () => {
    const out = html(<Exploited {...props(Exploited, { origin: "https://x", ...exampleList })} />);
    expect(out.match(/<h1/g)).toHaveLength(1);
    expect(out).toContain('href="/exploited/examplevpn-path-traversal"');
    expect(out).toContain("11 Oct 2026");
    expect(out).toContain("Confirmed by an analyst as an attempt against CVE-2099-0001");
    expect(out).toContain("We assess as an attempt against FOILED-DEMO-0002");
  });

  it("has an empty state", () => {
    const out = html(<Exploited {...props(Exploited, { origin: "https://x", items: [] })} />);
    expect(out).toContain("No write-ups are published yet.");
  });

  it("escapes a hostile title and does not link a bad canonical path", () => {
    const item = {
      ...exampleList.items[0],
      title: "<script>x</script>",
      canonical_path: "javascript:alert(1)",
    };
    const out = html(<Exploited {...props(Exploited, { origin: "https://x", items: [item] })} />);
    expect(out).not.toContain("<script>");
    expect(out).not.toContain("javascript:");
    expect(out).toContain('href="/exploited/examplevpn-path-traversal"');
  });
});

describe("exploit page", () => {
  const render = (page: PublicExploitPage | null) =>
    html(<Exploit {...props(Exploit, { origin: "https://x", page })} />);

  it("has one h1, TLP:CLEAR, the timeline, payload and IOCs", () => {
    const out = render(examplePage);
    expect(out.match(/<h1/g)).toHaveLength(1);
    expect(out).toContain("TLP:CLEAR");
    expect(out).toContain("First seen on Foiled sensors");
    expect(out).toContain("Advisory published");
    expect(out).toContain("Confirmed by an analyst");
    expect(out).toContain("03 Oct 2026");
    expect(out).toContain("Redacted payload");
    expect(out).toContain("192.0.2[.]10");
    expect(out).toContain("hxxps://example[.]com/payload");
    expect(out).toContain("only after the release delay and analyst confirmation");
  });

  it("uses we assess as for unconfirmed links and Confirmed only for confirmed ones", () => {
    const out = render(examplePage);
    expect(out).toContain("Confirmed by an analyst as an attempt against CVE-2099-0001");
    expect(out).toContain("We assess as an attempt against FOILED-DEMO-0001");
    expect(out).toContain("We assess as technique T1190");

    const unconfirmed = render({
      ...examplePage,
      cves: examplePage.cves.map((c) => ({ ...c, wording: "we assess as" as const })),
      timeline: examplePage.timeline.filter((t) => t.kind !== "confirmed"),
    });
    expect(unconfirmed).not.toContain("Confirmed by an analyst");
    expect(unconfirmed).not.toContain("chip--confirmed");
  });

  it("never links an IOC and escapes hostile values", () => {
    const out = render({
      ...examplePage,
      redacted_payload: "<script>alert(1)</script>‮",
      iocs: [{ ...examplePage.iocs[0], display: "<img src=x onerror=alert(1)>" }],
    });
    expect(out).not.toContain("<script");
    expect(out).not.toContain("<img");
    expect(out).toContain("\\u{202e}");
    expect(out).not.toContain("192.0.2");
  });

  it("renders a not found page for a missing write-up", () => {
    const out = render(null);
    expect(out).toContain("Not found");
    expect(out).toContain('href="/exploited"');
  });
});

describe("public pages and client navigation", () => {
  const sources = import.meta.glob(
    ["./PublicShell.tsx", "./ArticleBody.tsx", "../routes/public/*.tsx"],
    {
      query: "?raw",
      import: "default",
      eager: true,
    },
  ) as Record<string, string>;

  // /__manifest 404s on the public surface. Plain anchors navigate with a
  // document request and never ask for it; Link, Form and fetchers would.
  it("link with plain anchors only, so they never need /__manifest", () => {
    expect(Object.keys(sources).length).toBeGreaterThanOrEqual(4);
    for (const [file, src] of Object.entries(sources)) {
      expect(src, file).not.toMatch(/<(Link|NavLink|Form)\b|\buse(Navigate|Fetcher|Submit)\b/);
    }
  });
});
