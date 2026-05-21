import { CaseHeader } from "@/components/case-header";
import { ChatConsole } from "@/components/chat-console";
import { getSuggestedQuestions, type SuggestedQuestion } from "@/lib/api";
import { loadAudit, loadFindings } from "@/lib/server";
import { tabs } from "../../tabs";

export default async function ChatPage({ params }: { params: { id: string } }) {
  const [audit, { items }] = await Promise.all([loadAudit(params.id), loadFindings(params.id)]);
  let suggested: SuggestedQuestion[] = [];
  try {
    suggested = await getSuggestedQuestions(params.id);
  } catch {
    suggested = [];
  }
  return (
    <>
      <CaseHeader
        caseNo={audit.id.toUpperCase().slice(0, 12)}
        source={audit.source_ref}
        generatedAt={audit.finished_at ?? "—"}
        tabs={tabs(params.id, "chat")}
      />

      <section className="mb-8 grid grid-cols-12 gap-x-6 gap-y-4">
        <div className="col-span-12 md:col-span-7">
          <div className="term-label">ask virgil</div>
          <h2 className="mt-3 font-display text-[clamp(36px,5vw,68px)] leading-[1.02] tracking-tight">
            <span className="text-bone">ask</span>{" "}
            <span className="italic text-signal-live">virgil.</span>
          </h2>
          <p className="mt-4 max-w-[52ch] font-mono text-[13px] leading-[1.7] text-bone-dim">
            <span className="text-bone-ghost">{"//"}</span> virgil reads this audit's findings to answer your question.
            it cites the finding it pulled from. if the question needs information it doesn't have, it'll say so.
          </p>
        </div>
        <aside className="col-span-12 md:col-span-5 md:pl-4">
          <div className="border border-ink-300 bg-ink-50 px-4 py-3 font-mono text-[12px] leading-[1.6] text-bone-mute">
            <div className="mb-1 text-[10px] uppercase tracking-widest2 text-bone-ghost">good questions</div>
            <ul className="space-y-[2px]">
              <li><span className="text-signal-live">·</span> which finding should I fix first?</li>
              <li><span className="text-signal-live">·</span> explain the SHA1 issue in src/x.py</li>
              <li><span className="text-signal-live">·</span> what's the business impact of finding #0a?</li>
              <li><span className="text-signal-live">·</span> show me everything tagged secret-history</li>
            </ul>
          </div>
        </aside>
      </section>

      <ChatConsole auditId={params.id} findings={items} suggested={suggested} />
    </>
  );
}
