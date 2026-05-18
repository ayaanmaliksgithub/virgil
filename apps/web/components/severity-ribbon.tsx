import clsx from "clsx";
import type { Severity } from "@/lib/types";

const ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];
const COLOR: Record<Severity, string> = {
  Critical: "text-signal-critical",
  High: "text-signal-high",
  Medium: "text-signal-medium",
  Low: "text-signal-low",
  Informational: "text-signal-info",
};
const CODE: Record<Severity, string> = {
  Critical: "CRIT", High: "HIGH", Medium: "MED", Low: "LOW", Informational: "INFO",
};

/**
 * Severity distribution as a stacked horizontal bar — proportions are felt,
 * not just counted. Each cell is a single hex address so it still reads like
 * a memory map.
 */
export function SeverityRibbon({
  breakdown,
}: {
  breakdown: Record<Severity, number>;
}) {
  const total = ORDER.reduce((s, k) => s + (breakdown[k] || 0), 0) || 1;
  return (
    <div>
      <div className="flex h-[18px] w-full overflow-hidden border border-ink-300">
        {ORDER.map((k) => {
          const n = breakdown[k] || 0;
          const pct = (n / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={k}
              title={`${k}: ${n}`}
              className={clsx("relative h-full", COLOR[k])}
              style={{ width: `${pct}%`, backgroundColor: "currentColor" }}
            />
          );
        })}
      </div>

      <ol className="mt-3 grid grid-cols-5 gap-px bg-ink-300">
        {ORDER.map((k, i) => (
          <li
            key={k}
            className="grid grid-cols-1 gap-1 bg-ink-50 px-3 py-3 font-mono"
          >
            <span className="flex items-baseline justify-between text-[10px] uppercase tracking-widest2 text-bone-ghost">
              <span className="text-ink-400 tabular">0x{(i * 0x10).toString(16).padStart(2, "0")}</span>
              <span className={COLOR[k]}>[{CODE[k]}]</span>
            </span>
            <span className="font-display text-[28px] leading-none tabular text-bone">
              {String(breakdown[k] || 0).padStart(2, "0")}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}
