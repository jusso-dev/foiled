export interface SegmentOption<T extends string> {
  value: T;
  label: string;
  /** Extra text for the tooltip and screen readers, for example "coming soon". */
  hint?: string;
}

export interface SegmentedToggleProps<T extends string> {
  options: readonly SegmentOption<T>[];
  value: T;
  onChange?: (value: T) => void;
  /** Accessible name for the group, for example "Map view". */
  label: string;
  className?: string;
}

/** Buttons in a joined group. The active segment has a red-deep fill. */
export function SegmentedToggle<T extends string>({
  options,
  value,
  onChange,
  label,
  className,
}: SegmentedToggleProps<T>) {
  return (
    <fieldset className={className ? `seg ${className}` : "seg"}>
      <legend className="sr-only">{label}</legend>
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            className={on ? "seg__btn seg__btn--on" : "seg__btn"}
            aria-pressed={on}
            title={o.hint ? `${o.label}: ${o.hint}` : undefined}
            onClick={() => onChange?.(o.value)}
          >
            {o.label}
            {o.hint ? <span className="sr-only"> ({o.hint})</span> : null}
          </button>
        );
      })}
    </fieldset>
  );
}
