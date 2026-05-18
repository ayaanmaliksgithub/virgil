"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import clsx from "clsx";
import { ConfidenceChip } from "./confidence-chip";
import { SeverityChip, type Severity } from "./severity-chip";
import { OwaspBadge } from "./owasp-badge";
import type { Finding } from "@/lib/types";

const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];

type Lifecycle = "new" | "recurring" | "resolved";

export function FindingsTable({
  findings,
  auditId,
  hasBaseline = false,
  hasSuppressed = false,
  includeSuppressed = false,
}: {
  findings: Finding[];
  auditId: string;
  hasBaseline?: boolean;
  hasSuppressed?: boolean;
  includeSuppressed?: boolean;
}) {
  const [activeSev, setActiveSev] = useState<Set<Severity>>(new Set());
  const [activeCat, setActiveCat] = useState<Set<string>>(new Set());
  const [activeTool, setActiveTool] = useState<Set<string>>(new Set());
  const [activeLifecycle, setActiveLifecycle] = useState<Set<Lifecycle>>(new Set());
  const [kevOnly, setKevOnly] = useState(false);
  const [hideUnreachable, setHideUnreachable] = useState(true);
  const [query, setQuery] = useState("");

  const cats = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))).sort(),
    [findings]
  );
  const tools = useMemo(
    () => Array.from(new Set(findings.flatMap((f) => f.source_tool))).sort(),
    [findings]
  );

  const filtered = findings.filter((f) => {
    if (activeSev.size && !activeSev.has(f.severity)) return false;
    if (activeCat.size && !activeCat.has(f.category)) return false;
    if (activeTool.size && !f.source_tool.some((t) => activeTool.has(t))) return false;
    if (activeLifecycle.size && !(f.lifecycle && activeLifecycle.has(f.lifecycle as Lifecycle))) return false;
    if (kevOnly && !f.kev) return false;
    if (hideUnreachable && f.reachable === false) return false;
    if (query) {
      const q = query.toLowerCase();
      const hay = [
        f.title, f.category, f.owasp_category, f.cwe, f.cve,
        ...f.affected_files,
      ].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const sorted = filtered.slice().sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  const kevCount = findings.filter((f) => f.kev).length;
  const unreachableCount = findings.filter((f) => f.reachable === false).length;
  const hasFilter = activeSev.size || activeCat.size || activeTool.size || activeLifecycle.size || kevOnly || !hideUnreachable || query;

  return (
    <div className="grid grid-cols-12 gap-x-6">
      {/* FILTER RAIL */}
      <aside className="col-span-12 lg:col-span-3 space-y-6">
        <div>
          <div className="term-label mb-2">grep</div>
          <div className="flex items-baseline gap-2 border border-ink-300 bg-ink-50 px-3 py-2 font-mono text-[12px]">
            <span className="text-signal-live">$</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="title · file · cwe · cve"
              className="w-full bg-transparent text-bone caret-signal-live outline-none placeholder:text-bone-fog"
            />
          </div>
        </div>

        <FilterGroup
          label="severity"
          options={SEV_ORDER}
          active={activeSev}
          onToggle={(v) => toggle(setActiveSev, v as Severity)}
          render={(s) => <SeverityChip severity={s as Severity} size="sm" />}
        />
        <FilterGroup
          label="category"
          options={cats}
          active={activeCat}
          onToggle={(v) => toggle(setActiveCat, v)}
        />
        <FilterGroup
          label="scanner"
          options={tools}
          active={activeTool}
          onToggle={(v) => toggle(setActiveTool, v)}
        />

        {unreachableCount > 0 && (
          <button
            type="button"
            onClick={() => setHideUnreachable((v) => !v)}
            className={clsx(
              "block w-full border px-3 py-2 text-left font-mono text-[11px]",
              hideUnreachable
                ? "border-ink-300 bg-ink-50 text-bone-mute hover:text-bone"
                : "border-bone-mute bg-ink text-bone"
            )}
          >
            unreachable deps · {unreachableCount} hidden
            <div className="mt-1 text-[9px] uppercase tracking-widest2 text-bone-ghost">
              {hideUnreachable ? "$ click to show" : "$ filter OFF — click to hide"}
            </div>
          </button>
        )}

        {kevCount > 0 && (
          <button
            type="button"
            onClick={() => setKevOnly((v) => !v)}
            className={clsx(
              "block w-full border px-3 py-2 text-left font-mono text-[11px]",
              kevOnly
                ? "border-signal-critical bg-ink text-signal-critical"
                : "border-ink-300 bg-ink-50 text-bone-mute hover:text-signal-critical"
            )}
          >
            [ KEV ] cisa kev hits · {kevCount}
            <div className="mt-1 text-[9px] uppercase tracking-widest2 text-bone-ghost">
              {kevOnly ? "$ filter ACTIVE — click to clear" : "$ click to filter"}
            </div>
          </button>
        )}

        {hasBaseline && (
          <FilterGroup
            label="lifecycle · vs baseline"
            options={["new", "recurring"] as Lifecycle[]}
            active={activeLifecycle as unknown as Set<string>}
            onToggle={(v) => toggle(setActiveLifecycle, v as Lifecycle)}
            render={(v) => <LifecyclePill lifecycle={v as Lifecycle} />}
          />
        )}

        {hasSuppressed && (
          <a
            href={includeSuppressed
              ? `/audits/${auditId}/findings`
              : `/audits/${auditId}/findings?include_suppressed=true`}
            className="block font-mono text-[10px] uppercase tracking-widest2 text-bone-mute hover:text-signal-live"
          >
            $ {includeSuppressed ? "hide" : "show"} suppressed
          </a>
        )}

        {hasFilter ? (
          <button
            type="button"
            onClick={() => { setActiveSev(new Set()); setActiveCat(new Set()); setActiveTool(new Set()); setActiveLifecycle(new Set()); setKevOnly(false); setHideUnreachable(true); setQuery(""); }}
            className="font-mono text-[10px] uppercase tracking-widest2 text-bone-mute hover:text-signal-critical"
          >
            $ unset filters
          </button>
        ) : null}
      </aside>

      {/* LEDGER */}
      <div className="col-span-12 lg:col-span-9">
        <div className="mb-2 flex items-baseline justify-between">
          <span className="term-label">ledger · n={sorted.length}/{findings.length}</span>
          <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
            sort=severity.desc
          </span>
        </div>

        <div className="border border-ink-300 bg-ink-50">
          <div className="grid grid-cols-[92px_1fr_140px_140px] gap-3 border-b border-ink-300 px-4 py-2 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
            <span>offset</span>
            <span>entry</span>
            <span className="text-right">conf</span>
            <span className="text-right">source</span>
          </div>

          {sorted.map((f, i) => (
            <Link
              key={f.id}
              href={`/audits/${auditId}/findings/${f.id}`}
              className="group grid grid-cols-[92px_1fr_140px_140px] items-start gap-3 border-b border-ink-300 px-4 py-3 last:border-b-0 hover:bg-ink-100"
            >
              <span className="pt-1 font-mono text-[11px] text-ink-400 tabular">
                0x{(i * 0x20).toString(16).padStart(8, "0")}
              </span>

              <div className="min-w-0">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <SeverityChip severity={f.severity} size="sm" />
                  {f.lifecycle ? <LifecyclePill lifecycle={f.lifecycle as Lifecycle} /> : null}
                  {f.suppressed ? (
                    <span
                      title={f.suppression_reason ?? "suppressed"}
                      className="font-mono text-[9px] uppercase tracking-widest2 text-bone-ghost"
                    >
                      [ suppressed ]
                    </span>
                  ) : null}
                  <h3
                    className={clsx(
                      "font-mono text-[14px] group-hover:text-signal-live",
                      f.suppressed ? "text-bone-mute line-through decoration-ink-400" : "text-bone"
                    )}
                  >
                    {f.title}
                  </h3>
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-bone-mute">
                  <span className="text-bone-ghost uppercase tracking-widest2">{f.category}</span>
                  {f.owasp_category && <OwaspBadge category={f.owasp_category} />}
                  {f.cwe && <span className="text-bone-mute">· {f.cwe}</span>}
                  {f.cve && <span className="text-signal-high">· {f.cve}</span>}
                  {f.kev && (
                    <span
                      title="CISA Known Exploited Vulnerability"
                      className="font-mono text-[9px] uppercase tracking-widest2 text-signal-critical"
                    >
                      · [ KEV ]
                    </span>
                  )}
                  {f.reachable === false && (
                    <span
                      title="vulnerable package is in the lockfile but no source file imports it"
                      className="font-mono text-[9px] uppercase tracking-widest2 text-bone-ghost"
                    >
                      · [ unreach ]
                    </span>
                  )}
                  {typeof f.epss_score === "number" && f.epss_score >= 0.5 && (
                    <span
                      title={`EPSS percentile ${f.epss_percentile?.toFixed(2) ?? "?"}`}
                      className="font-mono text-[9px] uppercase tracking-widest2 text-signal-high"
                    >
                      · EPSS={f.epss_score.toFixed(2)}
                    </span>
                  )}
                </div>
                <div className="mt-1 font-mono text-[11px] text-bone-ghost">
                  {f.affected_files.slice(0, 2).map((af, j) => (
                    <span key={j}>
                      {j ? <span className="text-ink-400"> · </span> : null}
                      <span>{af}</span>
                      {f.affected_lines[j] && <span className="text-bone-fog">:L{f.affected_lines[j].start}</span>}
                    </span>
                  ))}
                  {f.affected_files.length > 2 && (
                    <span className="text-ink-400"> · +{f.affected_files.length - 2}</span>
                  )}
                </div>
              </div>

              <div className="flex justify-end pt-1">
                <ConfidenceChip confidence={f.confidence} />
              </div>
              <div className="flex flex-wrap justify-end gap-x-2 gap-y-1 pt-1 font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                {f.source_tool.map((t) => <span key={t}>[{t}]</span>)}
              </div>
            </Link>
          ))}
          {sorted.length === 0 && (
            <div className="px-4 py-8 text-center font-mono text-[12px] text-bone-mute">
              <span className="text-bone-ghost">{"//"}</span> no entries match the filter
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function LifecyclePill({ lifecycle }: { lifecycle: Lifecycle }) {
  const map: Record<Lifecycle, string> = {
    new: "text-signal-critical",
    recurring: "text-bone-mute",
    resolved: "text-signal-live",
  };
  const label: Record<Lifecycle, string> = { new: "NEW", recurring: "RECUR", resolved: "RESOLVED" };
  return (
    <span className={clsx("font-mono text-[9px] uppercase tracking-widest2", map[lifecycle])}>
      [ {label[lifecycle]} ]
    </span>
  );
}

function toggle<T>(setter: (fn: (s: Set<T>) => Set<T>) => void, v: T) {
  setter((s) => {
    const n = new Set(s);
    n.has(v) ? n.delete(v) : n.add(v);
    return n;
  });
}

function FilterGroup({
  label, options, active, onToggle, render,
}: {
  label: string;
  options: string[];
  active: Set<string>;
  onToggle: (v: string) => void;
  render?: (v: string) => React.ReactNode;
}) {
  return (
    <div>
      <div className="term-label mb-2">{label}</div>
      <ul className="border border-ink-300 bg-ink-50">
        {options.map((opt) => {
          const on = active.has(opt);
          return (
            <li key={opt}>
              <button
                type="button"
                onClick={() => onToggle(opt)}
                className={clsx(
                  "flex w-full items-center gap-3 border-b border-ink-300 px-3 py-1.5 text-left font-mono text-[11px] last:border-b-0 transition-colors",
                  on ? "bg-ink text-bone" : "text-bone-mute hover:text-bone"
                )}
              >
                <span
                  aria-hidden
                  className={clsx(
                    "inline-block h-[10px] w-[10px] border border-current",
                    on && "bg-signal-live"
                  )}
                />
                {render ? render(opt) : <span>{opt}</span>}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
