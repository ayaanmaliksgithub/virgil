import { AttackSurfaceGrid } from "@/components/attack-surface-grid";
import { CaseHeader } from "@/components/case-header";
import { loadAudit, loadFindings } from "@/lib/server";
import { tabs } from "../../tabs";

export default async function AttackSurfacePage({ params }: { params: { id: string } }) {
  const [audit, { items }] = await Promise.all([loadAudit(params.id), loadFindings(params.id)]);

  return (
    <>
      <CaseHeader
        caseNo={audit.id.toUpperCase().slice(0, 12)}
        source={audit.source_ref}
        generatedAt={audit.finished_at ?? "—"}
        tabs={tabs(params.id, "attack-surface")}
      />

      <section className="grid grid-cols-12 gap-x-6 gap-y-4 pb-10">
        <div className="col-span-12 md:col-span-7">
          <div className="term-label">attack_surface.map</div>
          <h2 className="mt-3 font-display text-[clamp(36px,5vw,68px)] leading-[1.02] tracking-tight">
            <span className="text-bone">six axes of</span>{" "}
            <span className="italic text-signal-live">exposure</span>
            <span className="text-bone-ghost">{"{}"}</span>
          </h2>
        </div>
        <aside className="col-span-12 md:col-span-5 md:pl-6">
          <p className="border-l border-ink-300 pl-4 font-mono text-[12px] leading-[1.6] text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> findings are bucketed against six common
            pillars so an analyst can read the codebase's posture at a glance. counts reflect the
            deduplicated ledger — a single underlying issue can only appear once.
          </p>
        </aside>
      </section>

      <AttackSurfaceGrid findings={items} auditId={params.id} />

      <section className="mt-10">
        <div className="term-label">method.note</div>
        <p className="mt-3 max-w-[80ch] border-l border-ink-300 pl-4 font-mono text-[12px] leading-[1.7] text-bone-dim">
          <span className="text-bone-ghost">{"//"}</span> pillars are deterministic groupings on top
          of the normalized finding schema — virgil does not invent categories. unmapped
          findings are intentionally absent from this view and remain in the full ledger.
        </p>
      </section>
    </>
  );
}
