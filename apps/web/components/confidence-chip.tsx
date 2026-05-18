import clsx from "clsx";

export type Confidence =
  | "High confidence"
  | "Medium confidence"
  | "Low confidence"
  | "Requires manual verification";

const MAP: Record<Confidence, { fill: number; cls: string; code: string }> = {
  "High confidence":   { fill: 3, cls: "text-signal-live",      code: "conf=hi" },
  "Medium confidence": { fill: 2, cls: "text-bone",             code: "conf=md" },
  "Low confidence":    { fill: 1, cls: "text-bone-mute",        code: "conf=lo" },
  "Requires manual verification": { fill: 0, cls: "text-signal-high", code: "conf=manual" },
};

export function ConfidenceChip({ confidence }: { confidence: Confidence }) {
  const m = MAP[confidence];
  return (
    <span
      title={confidence}
      className={clsx(
        "inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest2",
        m.cls
      )}
    >
      <span aria-hidden className="flex items-end gap-[2px]">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className={clsx(
              "w-[4px] border border-current",
              i === 0 && "h-[5px]",
              i === 1 && "h-[8px]",
              i === 2 && "h-[11px]",
              i < m.fill ? "bg-current" : "bg-transparent"
            )}
          />
        ))}
      </span>
      <span className="lowercase">{m.code}</span>
    </span>
  );
}
