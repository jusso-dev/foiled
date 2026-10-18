import type { ReactNode } from "react";
import { toPrintable } from "../lib/printable";
import { EXTERNAL_REL, isExternalHref, safeHref } from "../lib/public-format";
import type { BlockNode, InlineNode } from "../lib/public-types";

/**
 * A published write-up body (#35). The API sends a tree of blocks and
 * inlines, never HTML. Every string goes into a text node through
 * toPrintable, links keep only `https://` or site-relative targets, and
 * anything the tree does not describe is dropped. The page title is the only
 * h1, so headings map to h2 to h4.
 */
const list = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

export function ArticleBody({ blocks }: { blocks: readonly BlockNode[] }) {
  return (
    <div className="article">
      {withPaths<BlockNode>(blocks, "b").map(({ path, node }) => (
        <Block key={path} path={path} block={node} />
      ))}
    </div>
  );
}

/**
 * Give each node of the immutable body tree its path in the tree
 * (`b2`, `b2.i0`, `b3.l1.i4`) as a stable React key. The tree never
 * reorders on the client, so the path identifies a node for its lifetime.
 */
export function withPaths<T>(nodes: unknown, prefix: string): { path: string; node: T }[] {
  const out: { path: string; node: T }[] = [];
  let n = 0;
  for (const node of list<T>(nodes)) {
    out.push({ path: `${prefix}${n}`, node });
    n += 1;
  }
  return out;
}

const text = (v: unknown): string => (typeof v === "string" ? toPrintable(v) : "");

function Block({ block, path }: { block: BlockNode; path: string }) {
  switch (block?.type) {
    case "heading": {
      const Tag = block.level === 4 ? "h4" : block.level === 3 ? "h3" : "h2";
      return (
        <Tag className="article__h">
          <Inlines nodes={block.inlines} path={path} />
        </Tag>
      );
    }
    case "paragraph":
      return (
        <p>
          <Inlines nodes={block.inlines} path={path} />
        </p>
      );
    case "quote":
      return (
        <blockquote>
          <Inlines nodes={block.inlines} path={path} />
        </blockquote>
      );
    case "list": {
      const items = withPaths<InlineNode[]>(block.items, `${path}.l`).map((item) => (
        <li key={item.path}>
          <Inlines nodes={item.node} path={item.path} />
        </li>
      ));
      return block.ordered === true ? <ol>{items}</ol> : <ul>{items}</ul>;
    }
    case "code":
      return (
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard (WCAG 2.1.1).
        <pre className="article__code" tabIndex={0}>
          <code>{text(block.text)}</code>
        </pre>
      );
    case "rule":
      return <hr />;
    default:
      return null;
  }
}

function Inlines({ nodes, path }: { nodes: unknown; path: string }) {
  return (
    <>
      {withPaths<InlineNode>(nodes, `${path}.i`).map((n) => (
        <Inline key={n.path} node={n.node} />
      ))}
    </>
  );
}

function Inline({ node }: { node: InlineNode }): ReactNode {
  switch (node?.type) {
    case "text":
      return text(node.text);
    case "strong":
      return <strong>{text(node.text)}</strong>;
    case "emphasis":
      return <em>{text(node.text)}</em>;
    case "code":
      return <code className="article__inline-code">{text(node.text)}</code>;
    case "link": {
      const label = text(node.text);
      const href = safeHref(node.href);
      // An unsafe target keeps its words but loses the link.
      if (!href) return label;
      return isExternalHref(href) ? (
        <a href={href} rel={EXTERNAL_REL}>
          {label || toPrintable(href)}
        </a>
      ) : (
        <a href={href}>{label || href}</a>
      );
    }
    default:
      return null;
  }
}
