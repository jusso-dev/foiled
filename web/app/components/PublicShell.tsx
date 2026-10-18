import type { ReactNode } from "react";
import { FoiledMark } from "./icons";

export type PublicNavId = "exploited";

export const PUBLIC_NAV: readonly { id: PublicNavId; label: string; href: string }[] = [
  { id: "exploited", label: "Exploited", href: "/exploited" },
];

export interface PublicShellProps {
  children: ReactNode;
  active?: PublicNavId;
}

/**
 * Frame for the public pages (#35): wordmark, a link to the exploit list and a footer that
 * explains the confidence wording. Same tokens as the console, no sidebar.
 */
export function PublicShell({ children, active }: PublicShellProps) {
  return (
    <div className="pub">
      <header className="pub__head">
        <a className="pub__brand" href="/exploited">
          <FoiledMark size={28} />
          <span className="brand__wordmark pub__wordmark">FOILED</span>
          <span className="sr-only">, exploited vulnerabilities</span>
        </a>
        <nav aria-label="Main" className="pub__nav">
          {PUBLIC_NAV.map((item) => (
            <a
              key={item.id}
              href={item.href}
              className={item.id === active ? "pub__link pub__link--on" : "pub__link"}
              aria-current={item.id === active ? "page" : undefined}
            >
              {item.label}
            </a>
          ))}
        </nav>
      </header>
      <main className="pub__main">{children}</main>
      <footer className="pub__foot">
        <p>
          "We assess as" means our signals point to the link but an analyst has not confirmed it.
          "Confirmed" means an analyst has.
        </p>
        <p>Published as TLP:CLEAR. Counts come from Foiled sensors only.</p>
      </footer>
    </div>
  );
}
