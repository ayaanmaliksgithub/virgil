export function OwaspBadge({ category }: { category?: string | null }) {
  if (!category) return null;
  const m = /^(A\d{2})/.exec(category);
  const code = m ? m[1] : "—";
  const label = category.replace(/^A\d{2}:\d{4}\s*[-–]\s*/, "");
  return (
    <span className="inline-flex items-baseline gap-2 border border-ink-300 px-2 py-[2px] font-mono text-[10px] uppercase tracking-widest2 text-bone-mute">
      <span className="text-signal-live">{code}</span>
      <span className="text-ink-400">·</span>
      <span className="normal-case tracking-normal text-bone-dim">{label}</span>
    </span>
  );
}
