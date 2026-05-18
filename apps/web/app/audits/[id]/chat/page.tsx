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
    // Suggestions are a nice-to-have; the chat still works without them.
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
          <div className="term-label">ask_auditor()</div>
          <h2 className="mt-3 font-display text-[clamp(36px,5vw,68px)] leading-[1.02] tracking-tight">
            <span className="text-bone">a conversation</span>{" "}
            <span className="italic text-signal-live">bound to</span>{" "}
            <span className="text-bone">evidence.</span>
          </h2>
        </div>
        <aside className="col-span-12 md:col-span-5 md:pl-4">
          <p className="border-l border-ink-300 pl-4 font-mono text-[12px] leading-[1.7] text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> the auditor reads from this audit's
            stored findings only. answers cite specific entries; questions it can't ground in
            cited evidence are declined. exploit-shaped requests are refused outright.
          </p>
        </aside>
      </section>

      <ChatConsole auditId={params.id} findings={items} suggested={suggested} />
    </>
  );
}
