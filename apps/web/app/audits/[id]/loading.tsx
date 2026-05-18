/**
 * Loading skeleton for audit-scope pages. Renders during the server-side data
 * fetch so the user sees structure instead of a blank screen.
 */
export default function Loading() {
  return (
    <div className="animate-pulse">
      <div className="mb-10 panel pt-4">
        <span className="panel-title">case_t</span>
        <div className="grid grid-cols-1 gap-x-8 gap-y-2 px-5 py-4 md:grid-cols-[1fr_auto]">
          <div className="space-y-3">
            <div className="h-[10px] w-[180px] bg-ink-300" />
            <div className="h-[36px] w-[360px] bg-ink-200" />
          </div>
          <div className="space-y-2 self-end">
            <div className="h-[10px] w-[260px] bg-ink-300" />
            <div className="h-[10px] w-[200px] bg-ink-300" />
          </div>
        </div>
        <div className="grid grid-cols-5 border-t border-ink-300">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-[32px] border-r border-ink-300 bg-ink-50 last:border-r-0" />
          ))}
        </div>
      </div>

      <div className="space-y-4">
        <div className="h-[140px] panel bg-ink-50" />
        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-12 lg:col-span-8 h-[360px] panel bg-ink-50" />
          <div className="col-span-12 lg:col-span-4 h-[360px] panel bg-ink-50" />
        </div>
      </div>

      <div className="mt-8 font-mono text-[11px] uppercase tracking-widest2 text-bone-ghost">
        // loading audit context…
      </div>
    </div>
  );
}
