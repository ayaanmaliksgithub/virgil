"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { postChat, type SuggestedQuestion } from "@/lib/api";
import type { ChatTurn, Finding } from "@/lib/types";

/**
 * Chat with Virgil — a terminal-styled conversation grounded in the audit's
 * findings. Posts to the non-streaming /chat endpoint and renders the full
 * answer once received (kept simple to dodge dev-server SSE buffering).
 */
export function ChatConsole({
  auditId,
  findings,
  suggested = [],
}: {
  auditId: string;
  findings: Finding[];
  suggested?: SuggestedQuestion[];
}) {
  const [sessionId, setSessionId] = useState<string | undefined>(undefined);
  const [history, setHistory] = useState<ChatTurn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollerRef.current?.scrollTo({ top: scrollerRef.current.scrollHeight });
  }, [history, busy]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const msg = input.trim();
    if (!msg || busy) return;
    setBusy(true); setError(null);
    setHistory((h) => [
      ...h,
      { id: `tmp-${Date.now()}`, role: "user", content: msg, citations: [], created_at: new Date().toISOString() },
    ]);
    setInput("");
    try {
      const res = await postChat(auditId, msg, sessionId);
      setSessionId(res.session_id);
      setHistory(res.history);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid grid-cols-12 gap-x-6">
      <div className="col-span-12 lg:col-span-8">
        <div className="panel pt-4">
          <span className="panel-title">virgil · session={sessionId?.slice(0, 8) ?? "new"}</span>

          <div
            ref={scrollerRef}
            className="max-h-[560px] min-h-[340px] overflow-y-auto px-5 py-4 font-mono text-[13px] leading-[1.7]"
          >
            {history.length === 0 && (
              <div className="text-bone-mute">
                <div className="text-bone-ghost">{"//"} type a question below to start.</div>
                {suggested.length > 0 && (
                  <>
                    <div className="mt-4 text-[10px] uppercase tracking-widest2 text-bone-ghost">
                      derived from your top clusters
                    </div>
                    <ul className="mt-2 space-y-2">
                      {suggested.map((q, i) => (
                        <li key={i}>
                          <button
                            type="button"
                            onClick={() => setInput(q.prompt)}
                            className="group flex w-full items-start gap-3 border border-ink-300 bg-ink-50 px-3 py-2 text-left font-mono text-[12px] hover:border-signal-live"
                            disabled={busy}
                          >
                            <span className="text-signal-live shrink-0">$</span>
                            <span className="flex-1">
                              <span className="block text-bone group-hover:text-signal-live">
                                {q.label}
                              </span>
                              <span className="mt-1 block text-[11px] leading-[1.5] text-bone-mute">
                                {q.prompt}
                              </span>
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}

            {history.map((t, i) => (
              <Turn key={t.id || i} turn={t} auditId={auditId} findings={findings} />
            ))}

            {busy && (
              <div className="mt-3 font-mono text-[12px] text-bone-mute">
                <span className="text-signal-live">virgil&gt;</span> thinking
                <span className="term-cursor" />
              </div>
            )}
          </div>

          {error && (
            <div className="border-t border-signal-critical bg-ink-50 px-5 py-2 font-mono text-[11px] text-signal-critical">
              <span className="text-signal-critical/70">err:</span> {error}
            </div>
          )}

          <form onSubmit={onSubmit} className="grid grid-cols-[auto_1fr_auto] items-center gap-3 border-t border-ink-300 bg-ink px-5 py-3 font-mono text-[13px]">
            <span className="text-signal-live">user&gt;</span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ask a question about this audit…"
              disabled={busy}
              spellCheck={false}
              className="w-full bg-transparent text-bone caret-signal-live outline-none placeholder:text-bone-fog disabled:text-bone-mute"
              autoFocus
            />
            <button
              type="submit"
              disabled={busy || !input.trim()}
              className={clsx(
                "border px-3 py-1 font-mono text-[10px] uppercase tracking-widest2 transition-colors",
                busy || !input.trim()
                  ? "border-ink-400 text-bone-mute"
                  : "border-signal-live text-signal-live hover:bg-signal-live hover:text-ink"
              )}
            >
              ↵ send
            </button>
          </form>
        </div>
      </div>

      <aside className="col-span-12 lg:col-span-4 mt-6 lg:mt-0 space-y-6">
        <div>
          <div className="term-label mb-2">how virgil answers</div>
          <ul className="panel pt-4 text-[12px]">
            <span className="panel-title">contract</span>
            {DOES.map((line) => (
              <li key={line} className="grid grid-cols-[auto_1fr] gap-3 border-b border-ink-300 px-4 py-2 last:border-b-0 font-mono text-bone-mute">
                <span className="text-signal-live">✓</span> {line}
              </li>
            ))}
            {DOESNT.map((line) => (
              <li key={line} className="grid grid-cols-[auto_1fr] gap-3 border-b border-ink-300 px-4 py-2 last:border-b-0 font-mono text-bone-mute">
                <span className="text-signal-critical">✕</span> {line}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div className="term-label mb-2">what virgil sees</div>
          <p className="border-l border-ink-300 pl-3 font-mono text-[12px] leading-[1.7] text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> only this audit's findings: title, category,
            evidence (with secrets redacted), and the scanner metadata. no repo source, no web,
            no other audits, no chat history beyond this session.
          </p>
        </div>
      </aside>
    </div>
  );
}

function Turn({ turn, auditId, findings }: { turn: ChatTurn; auditId: string; findings: Finding[] }) {
  const isUser = turn.role === "user";
  const findingById = (id: string) => findings.find((f) => f.id === id);
  return (
    <div className="mt-4 first:mt-0">
      <div className="flex items-baseline gap-3">
        <span className={clsx("font-mono text-[12px]", isUser ? "text-bone" : "text-signal-live")}>
          {isUser ? "user>" : "virgil>"}
        </span>
        <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
          {fmtTs(turn.created_at)}
        </span>
      </div>
      <div className="mt-1 whitespace-pre-wrap font-mono text-[13px] leading-[1.7] text-bone-dim">
        {turn.content}
      </div>
      {turn.citations && turn.citations.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-2 text-bone-mute">
          <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">cites ⟶</span>
          {turn.citations.map((cid) => {
            const f = findingById(cid);
            return (
              <Link
                key={cid}
                href={`/audits/${auditId}/findings/${cid}`}
                className="inline-flex items-baseline gap-2 border border-ink-300 px-2 py-[1px] font-mono text-[10px] uppercase tracking-widest2 text-bone-mute hover:border-signal-live hover:text-signal-live"
              >
                <span className="text-signal-live">[{cid.slice(0,8)}]</span>
                <span className="normal-case tracking-normal text-bone-mute truncate max-w-[24ch]">
                  {f ? f.title : "finding"}
                </span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

function fmtTs(iso: string) {
  try {
    const d = new Date(iso);
    return d.toISOString().slice(11, 23);
  } catch {
    return "--:--:--.---";
  }
}

const DOES = [
  "answers come from this audit's findings",
  "every claim cites the finding it came from",
  "says 'I don't know' rather than guessing",
];

const DOESNT = [
  "writes exploits or proofs-of-concept",
  "hands out exact patches or code diffs",
  "reproduces an attack step-by-step",
];
