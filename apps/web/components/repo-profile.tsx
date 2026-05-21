"use client";

import { useEffect, useState } from "react";

/**
 * Live repo profile panel.
 *
 * Reads from the same /v1/audits/[id] endpoint PhaseTimeline polls. As the
 * worker advances through analyzing → scanning, the profile fields fill in
 * without a page refresh. Stops polling once the audit reaches terminal
 * state or once a non-empty profile has landed (whichever first).
 */

type Profile = {
  languages?: Record<string, number>;
  package_managers?: string[];
  frameworks?: string[];
  iac?: string[];
  loc?: number;
  file_count?: number;
  narrative?: string;
};

type AuditLite = {
  state?: string;
  phase?: string;
  profile?: Profile | null;
};

const POLL_MS = 1500;

export function RepoProfile({
  auditId,
  initial,
}: {
  auditId: string;
  initial: AuditLite;
}) {
  const [audit, setAudit] = useState<AuditLite>(initial);

  useEffect(() => {
    if (!auditId || auditId === "demo") return;
    if (isTerminal(audit) && hasProfile(audit)) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const tick = async () => {
      if (cancelled) return;
      try {
        const r = await fetch(`/api/v1/audits/${auditId}`, { cache: "no-store" });
        if (!r.ok) throw new Error(String(r.status));
        const a = (await r.json()) as AuditLite;
        if (cancelled) return;
        setAudit(a);
        if (isTerminal(a)) return; // stop polling
      } catch {
        // transient — try again
      }
      timer = setTimeout(tick, POLL_MS);
    };

    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auditId]);

  const p = audit.profile || ({} as Profile);

  return (
    <>
      <div>
        <div className="mb-2 term-label">repo_profile_t</div>
        <div className="panel pt-4">
          <span className="panel-title">profile</span>
          <Row addr="0x00" label="lang"      value={fmtLangs(p.languages)} />
          <Row addr="0x10" label="pkg.mgr"   value={p.package_managers?.join(" · ") || "—"} />
          <Row addr="0x20" label="framework" value={p.frameworks?.join(" · ") || "—"} />
          <Row addr="0x30" label="iac"       value={p.iac?.join(" · ") || "—"} />
          <Row addr="0x40" label="files"     value={p.file_count != null ? String(p.file_count) : "—"} />
          <Row addr="0x50" label="loc"       value={p.loc != null ? String(p.loc) : "—"} last />
        </div>
      </div>

      {p.narrative && (
        <div>
          <div className="mb-2 term-label">auditor.note</div>
          <div className="panel pt-4">
            <span className="panel-title">stdout</span>
            <p className="px-5 py-4 font-mono text-[12px] leading-[1.6] text-bone-dim">
              <span className="text-bone-ghost">{"//"}</span> {p.narrative}
            </p>
          </div>
        </div>
      )}
    </>
  );
}

function Row({ addr, label, value, last }: { addr: string; label: string; value: string; last?: boolean }) {
  return (
    <div className={`grid grid-cols-[60px_100px_1fr] items-baseline gap-3 px-4 py-2 font-mono text-[12px] ${last ? "" : "border-b border-ink-300"}`}>
      <span className="text-ink-400 tabular text-[10px] uppercase tracking-widest2">{addr}</span>
      <span className="text-bone-ghost text-[10px] uppercase tracking-widest2">{label}</span>
      <span className="text-bone-dim break-words">{value}</span>
    </div>
  );
}

function fmtLangs(l?: Record<string, number>): string {
  if (!l || Object.keys(l).length === 0) return "—";
  const entries = Object.entries(l).sort((a, b) => b[1] - a[1]).slice(0, 4);
  return entries.map(([lang, n]) => `${lang.toLowerCase()}(${n})`).join(" · ");
}

function isTerminal(a: AuditLite): boolean {
  return a.state === "succeeded" || a.state === "failed";
}
function hasProfile(a: AuditLite): boolean {
  const p = a.profile || ({} as Profile);
  return !!(p.languages || p.package_managers?.length || p.frameworks?.length);
}
