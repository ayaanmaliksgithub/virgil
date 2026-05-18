import clsx from "clsx";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

const MAP: Record<Severity, { code: string; cls: string }> = {
  Critical:      { code: "CRIT", cls: "text-signal-critical" },
  High:          { code: "HIGH", cls: "text-signal-high" },
  Medium:        { code: "MED",  cls: "text-signal-medium" },
  Low:           { code: "LOW",  cls: "text-signal-low" },
  Informational: { code: "INFO", cls: "text-signal-info" },
};

/**
 * Bracketed severity tag — looks like a log level. `[ CRIT ]`, `[ HIGH ]`, etc.
 * Glyphs are gone; the bracket *is* the visual identity now.
 */
export function SeverityChip({
  severity,
  size = "md",
}: {
  severity: Severity;
  size?: "sm" | "md";
}) {
  const m = MAP[severity];
  return (
    <span className={clsx("tag", m.cls, size === "sm" ? "text-[9px]" : "text-[10px]")}>
      {m.code}
    </span>
  );
}
