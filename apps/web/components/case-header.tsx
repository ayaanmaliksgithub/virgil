import Link from "next/link";
import clsx from "clsx";

type Tab = { href: string; label: string; active?: boolean };

/**
 * Audit case header rendered as a memory-dump file header — case_id in a
 * fixed-width address column, source as a path string, timestamps as monotonic
 * counters. Tabs read like `0x00:console` / `0x01:findings` / etc.
 */
export function CaseHeader({
  caseNo,
  source,
  generatedAt,
  tabs,
}: {
  caseNo: string;
  source: string;
  generatedAt?: string;
  tabs: Tab[];
}) {
  return (
    <section className="mb-10">
      <div className="panel pt-4">
        <span className="panel-title">case_t</span>
        <div className="grid grid-cols-1 gap-x-8 gap-y-2 px-5 py-4 md:grid-cols-[1fr_auto]">
          <div>
            <div className="flex items-baseline gap-3 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
              <span className="text-ink-400 tabular">0x00000000</span>
              <span>case_id</span>
            </div>
            <h1 className="mt-1 font-display text-[clamp(32px,4vw,52px)] leading-[0.95] tracking-tight">
              <span className="text-bone-ghost">№ </span>
              <span className="text-bone">{caseNo}</span>
              <span className="text-signal-live term-cursor" />
            </h1>
          </div>
          <dl className="grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-1 self-end font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost md:justify-self-end">
            <dt>source ⟶</dt>
            <dd className="text-bone-dim normal-case tracking-normal">{source}</dd>
            {generatedAt && (
              <>
                <dt>finished ⟶</dt>
                <dd className="text-bone-dim normal-case tracking-normal">{generatedAt}</dd>
              </>
            )}
          </dl>
        </div>
      </div>

      <nav className="mt-px grid grid-cols-2 border border-ink-300 bg-ink-50 sm:grid-cols-3 md:grid-cols-5">
        {tabs.map((t, i) => (
          <Link
            key={t.href}
            href={t.href}
            className={clsx(
              "group relative flex items-baseline gap-3 border-r border-ink-300 px-4 py-2 font-mono text-[11px] uppercase tracking-widest2 transition-colors last:border-r-0",
              t.active
                ? "bg-ink text-bone"
                : "text-bone-mute hover:text-bone"
            )}
          >
            <span
              className={clsx(
                "tabular",
                t.active ? "text-signal-live" : "text-ink-400 group-hover:text-bone-ghost"
              )}
            >
              0x{i.toString(16).padStart(2, "0")}
            </span>
            <span>{t.label}</span>
            {t.active && <span className="text-signal-live">{"▍"}</span>}
          </Link>
        ))}
      </nav>
    </section>
  );
}
