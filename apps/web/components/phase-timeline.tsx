import clsx from "clsx";
import type { Phase } from "@/lib/types";

const PHASES: { key: Phase; label: string; n: string }[] = [
  { key: "queued",      label: "queued",      n: "0x00" },
  { key: "cloning",     label: "cloning",     n: "0x01" },
  { key: "analyzing",   label: "analyzing",   n: "0x02" },
  { key: "scanning",    label: "scanning",    n: "0x03" },
  { key: "correlating", label: "correlating", n: "0x04" },
  { key: "reporting",   label: "reporting",   n: "0x05" },
  { key: "completed",   label: "completed",   n: "0x06" },
];

function indexOf(p: Phase): number {
  const i = PHASES.findIndex((x) => x.key === p);
  return i < 0 ? 0 : i;
}

const BAR_WIDTH = 26;

function bar(done: number, active: boolean) {
  const filled = Math.round((done / (PHASES.length - 1)) * BAR_WIDTH);
  const head = active ? "▒" : "";
  const rest = "·".repeat(Math.max(0, BAR_WIDTH - filled - (active ? 1 : 0)));
  const lead = "█".repeat(Math.max(0, filled - (active ? 1 : 0)));
  return `${lead}${head}${rest}`;
}

export function PhaseTimeline({ current, failed }: { current: Phase; failed?: boolean }) {
  const idx = indexOf(current);
  const running = !failed && current !== "completed";
  return (
    <div className="panel pt-4">
      <span className="panel-title">phase_ledger</span>

      <div className="flex items-baseline justify-between border-b border-ink-300 px-5 py-3 font-mono text-[11px]">
        <span className="flex items-center gap-3">
          <span className="text-bone-ghost uppercase tracking-widest2">progress</span>
          <span className={clsx("tabular", failed ? "text-signal-critical" : "text-signal-live")}>
            [{bar(idx, running)}]
          </span>
        </span>
        <span className="text-bone-ghost tabular">
          {String(idx + 1).padStart(2, "0")}/{PHASES.length.toString().padStart(2, "0")}
        </span>
      </div>

      <ol>
        {PHASES.map((p, i) => {
          const state =
            failed && i === idx ? "failed"
            : i < idx ? "done"
            : i === idx ? "active"
            : "pending";
          return (
            <li
              key={p.key}
              className={clsx(
                "grid grid-cols-[88px_24px_1fr_140px] items-center gap-4 border-b border-ink-300 px-5 py-2 last:border-b-0 font-mono text-[12px]",
                (state === "active" || state === "failed") && "bg-ink",
              )}
            >
              <span className="text-ink-400 tabular text-[10px] uppercase tracking-widest2">{p.n}</span>
              <span className={clsx("text-center", glyphClass(state))}>{glyph(state)}</span>
              <span
                className={clsx(
                  "uppercase tracking-widest2 text-[11px]",
                  state === "active" && "text-bone",
                  state === "done" && "text-bone-mute",
                  state === "pending" && "text-bone-ghost",
                  state === "failed" && "text-signal-critical",
                )}
              >
                {p.label}
              </span>
              <span className="justify-self-end font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                {state === "done" && "[ ok ]"}
                {state === "active" && (
                  <span className="text-signal-live">
                    [ run · <span className="animate-pulse">…</span> ]
                  </span>
                )}
                {state === "pending" && "[ waiting ]"}
                {state === "failed" && <span className="text-signal-critical">[ failed ]</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function glyph(state: "done" | "active" | "pending" | "failed") {
  if (state === "done")    return "✓";
  if (state === "active")  return "▶";
  if (state === "failed")  return "✕";
  return "·";
}
function glyphClass(state: "done" | "active" | "pending" | "failed") {
  if (state === "done")    return "text-bone-mute";
  if (state === "active")  return "text-signal-live";
  if (state === "failed")  return "text-signal-critical";
  return "text-ink-400";
}
