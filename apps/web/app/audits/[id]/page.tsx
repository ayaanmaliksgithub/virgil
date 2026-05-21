import { CaseHeader } from "@/components/case-header";
import { ConsoleStream } from "@/components/console-stream";
import { PhaseTimeline } from "@/components/phase-timeline";
import { RepoProfile } from "@/components/repo-profile";
import { QueueBanner } from "@/components/queue-banner";
import { loadAudit, loadQueueStatus } from "@/lib/server";
import { tabs } from "../tabs";

export default async function AuditConsolePage({ params }: { params: { id: string } }) {
  const audit = await loadAudit(params.id);
  // Initial queue snapshot rendered server-side so the page never flashes
  // through a "no queue info" state on first paint. The QueueBanner client
  // takes over polling from there and self-hides once `active` flips false.
  const queue = await loadQueueStatus(params.id);
  const generated = audit.finished_at ?? "—";
  const elapsed = audit.started_at && audit.finished_at
    ? humanElapsed(audit.started_at, audit.finished_at)
    : null;

  return (
    <>
      <CaseHeader
        caseNo={audit.id.toUpperCase().slice(0, 12)}
        source={audit.source_ref}
        generatedAt={generated}
        tabs={tabs(params.id, "console")}
      />

      {queue?.active && (
        <QueueBanner auditId={params.id} initial={queue} />
      )}

      <section className="grid grid-cols-12 gap-x-6 gap-y-8">
        <div className="col-span-12">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="term-label">phase ledger</span>
            <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
              state=<span className="text-bone-mute">{audit.state}</span>
              {elapsed && <> · elapsed=<span className="text-bone-mute">{elapsed}</span></>}
            </span>
          </div>
          <PhaseTimeline auditId={params.id} current={audit.phase} failed={audit.state === "failed"} />
        </div>

        <div className="col-span-12 lg:col-span-8">
          <div className="mb-2 term-label">console</div>
          <ConsoleStream auditId={params.id} />
        </div>

        <aside className="col-span-12 lg:col-span-4 space-y-6">
          <RepoProfile auditId={params.id} initial={{ state: audit.state, phase: audit.phase, profile: audit.profile }} />
        </aside>
      </section>
    </>
  );
}



function humanElapsed(a: string, b: string) {
  const ms = new Date(b).getTime() - new Date(a).getTime();
  const s = Math.max(0, Math.round(ms / 1000));
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}
