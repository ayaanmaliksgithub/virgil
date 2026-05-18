import { CaseHeader } from "@/components/case-header";
import { ConsoleStream } from "@/components/console-stream";
import { PhaseTimeline } from "@/components/phase-timeline";
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
          <PhaseTimeline current={audit.phase} failed={audit.state === "failed"} />
        </div>

        <div className="col-span-12 lg:col-span-8">
          <div className="mb-2 term-label">console</div>
          <ConsoleStream auditId={params.id} />
        </div>

        <aside className="col-span-12 lg:col-span-4 space-y-6">
          <div>
            <div className="mb-2 term-label">repo_profile_t</div>
            <div className="panel pt-4">
              <span className="panel-title">profile</span>
              <Row addr="0x00" label="lang"      value={fmtLangs(audit.profile?.languages)} />
              <Row addr="0x10" label="pkg.mgr"   value={audit.profile?.package_managers?.join(" · ") ?? "—"} />
              <Row addr="0x20" label="framework" value={audit.profile?.frameworks?.join(" · ") ?? "—"} />
              <Row addr="0x30" label="iac"       value={audit.profile?.iac?.join(" · ") ?? "—"} />
              <Row addr="0x40" label="files"     value={String(audit.profile?.file_count ?? "—")} />
              <Row addr="0x50" label="loc"       value={String(audit.profile?.loc ?? "—")} last />
            </div>
          </div>

          {audit.profile?.narrative && (
            <div>
              <div className="mb-2 term-label">auditor.note</div>
              <div className="panel pt-4">
                <span className="panel-title">stdout</span>
                <p className="px-5 py-4 font-mono text-[12px] leading-[1.6] text-bone-dim">
                  <span className="text-bone-ghost">{"//"}</span> {audit.profile.narrative}
                </p>
              </div>
            </div>
          )}
        </aside>
      </section>
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

function fmtLangs(l?: Record<string, number>) {
  if (!l) return "—";
  return Object.entries(l).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}(${v})`).join(" · ");
}

function humanElapsed(a: string, b: string) {
  const ms = new Date(b).getTime() - new Date(a).getTime();
  const s = Math.max(0, Math.round(ms / 1000));
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}
