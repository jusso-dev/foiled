import { Icon, type IconName } from "./icons";

export interface NavItemProps {
  label: string;
  href: string;
  icon: IconName;
  /** Count badge, for example new items since last visit. Hidden when 0 or absent. */
  count?: number;
  active?: boolean;
}

/** Sidebar link. Active state: red left rule, red-tinted fill. */
export function NavItem({ label, href, icon, count, active = false }: NavItemProps) {
  return (
    <a
      className={active ? "nav-item nav-item--on" : "nav-item"}
      href={href}
      aria-current={active ? "page" : undefined}
    >
      <Icon name={icon} />
      <span className="nav-item__label">{label}</span>
      {count ? (
        <span className="nav-item__badge">
          {count}
          <span className="sr-only"> new</span>
        </span>
      ) : null}
    </a>
  );
}
