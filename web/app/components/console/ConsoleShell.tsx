import { createContext, type ReactNode, useContext, useId } from "react";
import { Form, Link, useNavigation } from "react-router";
import { FoiledMark, Icon, type IconName } from "../icons";

export type ConsoleSection =
  | "overview"
  | "launch"
  | "decoys"
  | "attempts"
  | "review"
  | "writeups"
  | "radar"
  | "actors"
  | "campaigns"
  | "iocs"
  | "exports"
  | "quarantine"
  | "registry"
  | "audit";

export const CONSOLE_NAV: readonly {
  id: ConsoleSection;
  label: string;
  icon: IconName;
  href: string;
}[] = [
  { id: "overview", label: "Overview", icon: "live", href: "/" },
  { id: "launch", label: "Launch decoy", icon: "bolt", href: "/launch" },
  { id: "decoys", label: "Decoys", icon: "honeypots", href: "/decoys" },
  { id: "attempts", label: "Attempts", icon: "activity", href: "/attempts" },
  { id: "review", label: "Review queue", icon: "cve", href: "/review" },
  { id: "writeups", label: "Write-ups", icon: "payloads", href: "/writeups" },
  { id: "radar", label: "Radar", icon: "globe", href: "/radar" },
  { id: "campaigns", label: "Campaigns", icon: "attackers", href: "/campaigns" },
  { id: "actors", label: "Actor associations", icon: "ttps", href: "/actors" },
  { id: "iocs", label: "IOCs", icon: "iocs", href: "/iocs" },
  { id: "exports", label: "Exports", icon: "reports", href: "/exports" },
  { id: "quarantine", label: "Quarantine", icon: "malware", href: "/quarantine" },
  { id: "registry", label: "Hosts and sensors", icon: "layers", href: "/registry" },
  { id: "audit", label: "Audit log", icon: "api", href: "/audit" },
];

/** Which section a path belongs to, for the active nav item. */
export function sectionFor(pathname: string): ConsoleSection {
  const first = pathname.split("/")[1] ?? "";
  const hit = CONSOLE_NAV.find((n) => n.href === `/${first}`);
  return hit ? hit.id : "overview";
}

/** The session's CSRF token, provided by the console layout to every form. */
export const CsrfContext = createContext<string>("");

/** Hidden CSRF field. Every mutating form in the console includes one. */
export function CsrfField() {
  const csrf = useContext(CsrfContext);
  return <input type="hidden" name="csrf" value={csrf} />;
}

export interface ConsoleShellProps {
  children: ReactNode;
  pathname: string;
  operator: { id: string; tenant: string };
  /** Badge counts, for example open review items. */
  counts?: Partial<Record<ConsoleSection, number>>;
}

/**
 * The authenticated console frame: sidebar navigation, a search box that
 * jumps to an attempt, campaign, IOC or CVE, who is signed in, and sign out.
 */
export function ConsoleShell({ children, pathname, operator, counts = {} }: ConsoleShellProps) {
  const active = sectionFor(pathname);
  const navigation = useNavigation();
  const searchId = useId();
  const busy = navigation.state !== "idle";
  return (
    <div className="shell">
      <a className="skip-link" href="#console-main">
        Skip to content
      </a>
      <aside className="shell__side">
        <div className="brand">
          <FoiledMark />
          <div>
            <div className="brand__wordmark">FOILED</div>
            <div className="brand__tag">Operator console</div>
          </div>
        </div>
        <nav aria-label="Console">
          <ul className="nav">
            {CONSOLE_NAV.map((item) => {
              const on = item.id === active;
              const count = counts[item.id];
              return (
                <li key={item.id}>
                  <Link
                    className={on ? "nav-item nav-item--on" : "nav-item"}
                    to={item.href}
                    aria-current={on ? "page" : undefined}
                  >
                    <Icon name={item.icon} />
                    <span className="nav-item__label">{item.label}</span>
                    {count ? (
                      <span className="nav-item__badge">
                        {count}
                        <span className="sr-only"> open</span>
                      </span>
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <p className="motto">
          Real attackers.
          <br />
          Real behaviour.
          <br />
          <strong>Assessed, not guessed.</strong>
        </p>
      </aside>

      <div className="shell__main">
        <header className="topbar">
          <Form className="search" role="search" aria-label="Jump to" method="get" action="/search">
            <label htmlFor={searchId} className="sr-only">
              Jump to an attempt, campaign, IOC, CVE or source address
            </label>
            <Icon name="search" size={16} />
            <input
              id={searchId}
              name="q"
              type="search"
              autoComplete="off"
              maxLength={256}
              placeholder="Attempt id, campaign id, IOC, CVE or source IP"
            />
          </Form>
          <div className="console-user">
            <span className="muted">Signed in as</span> <span className="mono">{operator.id}</span>{" "}
            <span className="muted">tenant</span> <span className="mono">{operator.tenant}</span>
          </div>
          <Form method="post" action="/logout">
            <CsrfField />
            <button type="submit" className="btn">
              Sign out
            </button>
          </Form>
        </header>
        <output className="sr-only" aria-live="polite">
          {busy ? "Loading" : ""}
        </output>
        <main id="console-main" className="shell__content" aria-busy={busy} tabIndex={-1}>
          {busy ? (
            <div className="progress" aria-hidden="true">
              <span className="progress__bar" />
            </div>
          ) : null}
          {children}
        </main>
      </div>
    </div>
  );
}
