import type { ReactNode } from "react";

export interface PanelProps {
  title: string;
  /** Optional link in the header, for example "View all". */
  action?: { label: string; href: string };
  children: ReactNode;
  className?: string;
}

/** Card with an uppercase title row. */
export function Panel({ title, action, children, className }: PanelProps) {
  return (
    <section className={className ? `card panel ${className}` : "card panel"}>
      <header className="panel__head">
        <h2 className="panel__title">{title}</h2>
        {action ? (
          <a className="panel__action" href={action.href}>
            {action.label} <span aria-hidden="true">→</span>
          </a>
        ) : null}
      </header>
      {children}
    </section>
  );
}
