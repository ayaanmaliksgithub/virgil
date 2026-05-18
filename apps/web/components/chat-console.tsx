"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { streamChat, type StreamChatHandle, type SuggestedQuestion } from "@/lib/api";
import type { ChatTurn, Finding } from "@/lib/types";

/**
 * Ask-the-Auditor terminal.
 *
 * Transcript renders like an `irssi`/`mosh` log — each turn is prefixed with
 * `user@audit$` or `auditor>` and timestamps; citations resolve to links to the
 * underlying finding detail pages.
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
  // Live-streaming assistant text rendered into the transcript *before* the
  // `done` frame arrives. Once `done` lands, the official ChatTurn from the
  // server replaces this draft so safety-validated refusals never leave
  // partial unsafe output on screen.
  const [streamingText, setStreamingText] = useState<string>("");
  const streamRef = useRef<StreamChatHandle | null>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollerRef.current?.scrollTo({ top: scrollerRef.current.scrollHeight });
  }, [history, busy, streamingText]);

  // Cancel any in-flight stream if the component unmounts mid-response.
  useEffect(() => () => { streamRef.current?.cancel(); }, []);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const msg = input.trim();
    if (!msg || busy) return;
    setBusy(true); setError(null); setStreamingText("");
    setHistory((h) => [
      ...h,
      { id: `tmp-${Date.now()}`, role: "user", content: msg, citations: [], created_at: new Date().toISOString() },
    ]);
    setInput("");

    streamRef.current = streamChat(auditId, msg, sessionId, {
      onSession: (sid) => setSessionId(sid),
      onToken: (text) => setStreamingText((s) => s + text),
      onDone: (res) => {
        // `history` from the server is authoritative — it includes both turns
        // with their canonical IDs and (for the assistant) the post-safety
        // text. Drop our draft entirely; the server's version supersedes it.
        setHistory(res.history);
        setStreamingText("");
        setBusy(false);
        streamRef.current = null;
      },
      onError: (detail) => {
        setError(detail || "chat error");
        setStreamingText("");
        setBusy(false);
        streamRef.current = null;
      },
    });
  }

  return (
    <div className="grid grid-cols-12 gap-x-6">
      <div className="col-span-12 lg:col-span-8">
        <div className="panel pt-4">
          <span className="panel-title">ask_auditor() · session={sessionId?.slice(0, 8) ?? "new"}</span>

          {/* TRANSCRIPT */}
          <div
            ref={scrollerRef}
            className="max-h-[520px] min-h-[320px] overflow-y-auto px-5 py-4 font-mono text-[13px] leading-[1.7]"
          >
            {history.length === 0 && (
              <div className="text-bone-mute">
                <div className="text-bone-ghost">{"//"} no messages yet</div>
                {suggested.length > 0 ? (
                  <>
                    <div className="mt-2 text-bone-mute">
                      starter prompts derived from this audit's top clusters — click to load:
                    </div>
                    <ul className="mt-3 space-y-2">
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
                ) : (
                  <div className="mt-2 text-bone-mute">
                    ask about a finding, category, or affected file.
                  </div>
                )}
                <div className="mt-6 border-l-2 border-signal-critical pl-3 text-bone-mute">
                  <span className="font-mono text-[10px] uppercase tracking-widest2 text-signal-critical">policy</span> the auditor refuses exploit-shaped requests. it will not produce payloads, exact patches, diffs, or step-by-step reproduction.
                </div>
              </div>
            )}

            {history.map((t, i) => (
              <Turn key={t.id || i} turn={t} auditId={auditId} findings={findings} />
            ))}

            {/* Live streaming draft — replaced wholesale when `done` arrives. */}
            {busy && streamingText && (
              <div className="mt-4">
                <div className="flex items-baseline gap-3">
                  <span className="font-mono text-[12px] text-signal-live">auditor&gt;</span>
                  <span className="font-mono text-[10px] uppercase tracking-widest2 text-bone-ghost">
                    streaming
                  </span>
                </div>
                <div className="mt-1 whitespace-pre-wrap font-mono text-[13px] leading-[1.7] text-bone-dim">
                  {streamingText}
                  <span className="term-cursor" />
                </div>
              </div>
            )}

            {busy && !streamingText && (
              <div className="mt-3 font-mono text-[12px] text-bone-mute">
                <span className="text-signal-live">auditor&gt;</span> thinking
                <span className="term-cursor" />
              </div>
            )}
          </div>

          {error && (
            <div className="border-t border-signal-critical bg-ink-50 px-5 py-2 font-mono text-[11px] text-signal-critical">
              <span className="text-signal-critical/70">err:</span> {error}
            </div>
          )}

          {/* PROMPT */}
          <form onSubmit={onSubmit} className="grid grid-cols-[auto_1fr_auto] items-center gap-3 border-t border-ink-300 bg-ink px-5 py-3 font-mono text-[13px]">
            <span className="text-signal-live">user@audit$</span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ask the auditor…"
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

      <aside className="col-span-12 lg:col-span-4 mt-6 lg:mt-0">
        <div className="term-label mb-2">policy</div>
        <ul className="panel pt-4 text-[12px]">
          <span className="panel-title">contract</span>
          {POLICY.map((p) => (
            <li key={p.label} className="grid grid-cols-[auto_1fr] gap-3 border-b border-ink-300 px-4 py-2 last:border-b-0 font-mono text-bone-mute">
              <span className="text-signal-live">✓</span> {p.label}
            </li>
          ))}
          {NEVER.map((p) => (
            <li key={p} className="grid grid-cols-[auto_1fr] gap-3 border-b border-ink-300 px-4 py-2 last:border-b-0 font-mono text-bone-mute">
              <span className="text-signal-critical">✕</span> {p}
            </li>
          ))}
        </ul>

        <div className="mt-6">
          <div className="term-label mb-2">grounded.in</div>
          <p className="border-l border-ink-300 pl-3 font-mono text-[12px] leading-[1.7] text-bone-mute">
            <span className="text-bone-ghost">{"//"}</span> the auditor sees only this audit's
            findings — title, category, evidence (redacted), and the
            scanner-derived metadata. it has no access to the raw repo, no
            web browsing, and no other audits.
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
          {isUser ? "user@audit$" : "auditor>"}
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
                <span className="text-signal-live">[{cid}]</span>
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

const POLICY = [
  { label: "answers grounded in this audit's findings only" },
  { label: "citations resolve to specific finding ids" },
  { label: "refuses questions it can't answer from cited context" },
  { label: "every output passes the safety validator" },
];

const NEVER = [
  "no exploit payloads or PoCs",
  "no exact patches or diffs",
  "no step-by-step reproduction",
  "no operational attack guidance",
];
