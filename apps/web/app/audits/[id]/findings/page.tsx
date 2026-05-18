import { CaseHeader } from "@/components/case-header";
import { FindingsTable } from "@/components/findings-table";
import { SeverityRibbon } from "@/components/severity-ribbon";
import { loadAudit, loadFindings } from "@/lib/server";
import type { Severity } from "@/lib/types";
import { tabs } from "../../tabs";

export default async function FindingsPage({
  params,
  searchParams,
}: {
  params: { id: string };
  searchParams?: { include_suppressed?: string };
}) {
  const includeSuppressed = searchParams?.include_suppressed === "true";
  const [audit, { items }] = await Promise.all([
    loadAudit(params.id),
    loadFindings(params.id, { includeSuppressed }),
  ]);

  const breakdown: Record<Severity, number> = items.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 } as Record<Severity, number>
  );

  const hasBaseline = !!audit.baseline_audit_id;
  const hasSuppressed = items.some((f) => f.suppressed) || includeSuppressed;
  const kevHits = items.filter((f) => f.kev);

  return (
    <>
      <CaseHeader
        caseNo={audit.id.toUpperCase().slice(0, 12)}
        source={audit.source_ref}
        generatedAt={audit.finished_at ?? "—"}
        tabs={tabs(params.id, "findings")}
      />

      {kevHits.length > 0 && (
        <div className="mb-6 border-l-2 border-signal-critical bg-ink-50 px-4 py-3 font-mono text-[11px]">
          <div className="text-[10px] uppercase tracking-widest2 text-signal-critical">
            ⚠ cisa kev · {kevHits.length} active-exploit cve{kevHits.length === 1 ? "" : "s"} in this codebase
          </div>
          <p className="mt-1 text-bone-mute">
            <span className="text-bone-ghost">{"//"} </span>
            findings tagged{" "}
            <span className="text-signal-critical">[ KEV ]</span> map to CVEs that CISA has
            confirmed are being actively exploited. Triage these first.
          </p>
        </div>
      )}

      {hasBaseline && (
        <div className="mb-6 border-l-2 border-signal-live bg-ink-50 px-4 py-2 font-mono text-[11px] text-bone-mute">
          <span className="text-bone-ghost">{"//"} </span>
          baseline ={" "}
          <a
            href={`/audits/${audit.baseline_audit_id}/findings`}
            className="text-bone hover:text-signal-live"
          >
            0x{audit.baseline_audit_id!.replace(/-/g, "").slice(0, 12).toUpperCase()}
          </a>
          <span className="text-bone-ghost"> · new/recurring badges enabled · </span>
          <a
            href={`/api/v1/audits/${audit.id}/diff`}
            className="text-bone hover:text-signal-live"
          >
            $ cat diff.json
          </a>
        </div>
      )}

      <section className="mb-10">
        <div className="mb-2 term-label">severity.distribution</div>
        <SeverityRibbon breakdown={breakdown} />
      </section>

      <FindingsTable
        findings={items}
        auditId={params.id}
        hasBaseline={hasBaseline}
        hasSuppressed={hasSuppressed}
        includeSuppressed={includeSuppressed}
      />
    </>
  );
}
