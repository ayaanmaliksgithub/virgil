"use client";

import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { neutralizeToolNames } from "@/lib/tool-labels";

/**
 * Live audit console.
 *
 * DEMO  (auditId === "demo" or unset) — replays a baked tape.
 * LIVE  (any other auditId)           — polls /api/v1/audits/<id>/events.json
 *                                       every POLL_MS, advancing a cursor.
 *                                       Stops when audit reaches terminal state.
 *
 * Polling rather than SSE because the dev-server EventSource path proved
 * unreliable — polling is dumb, robust, and fine for ~10 lines/min throughput.
 */

const POLL_MS = 1500;

type Line = { id?: number; ts: string; phase: string; level: "info" | "warning" | "error"; message: string };
type ConnState = "idle" | "polling" | "done" | "error";

const DEMO_TAPE: Line[] = [
  { ts: "19:42:08.114", phase: "cloning",     level: "info",    message: "[sandbox] provisioning virgil/scanner:latest" },
  { ts: "19:42:09.812", phase: "cloning",     level: "info",    message: "[git]     clone --depth=1 --no-tags https://github.com/owasp/nodegoat" },
  { ts: "19:42:21.336", phase: "cloning",     level: "info",    message: "[git]     HEAD = 9f3c1d8" },
  { ts: "19:42:22.901", phase: "analyzing",   level: "info",    message: "[profile] lang=js(142) ts(38) · pkg=npm · fw=express · iac=docker,gha" },
  { ts: "19:42:24.180", phase: "scanning",    level: "info",    message: "[static] config=p/owasp-top-ten,p/security-audit,p/secrets · timeout=120" },
  { ts: "19:43:48.044", phase: "scanning",    level: "info",    message: "[static] rc=0 · raw=14" },
  { ts: "19:43:49.211", phase: "scanning",    level: "info",    message: "[deps]   fs --scanners=vuln,misconfig,secret · timeout=300" },
  { ts: "19:45:01.778", phase: "scanning",    level: "warning", message: "[deps]   1 misconfig source unresolved (continuing)" },
  { ts: "19:45:02.013", phase: "scanning",    level: "info",    message: "[secret] detect --no-git --redact" },
  { ts: "19:45:11.612", phase: "correlating", level: "info",    message: "[norm]    raw=27 → unified=8" },
  { ts: "19:45:12.119", phase: "correlating", level: "info",    message: "[norm]    agreement=2 · conf bumped → HI" },
  { ts: "19:45:13.040", phase: "reporting",   level: "info",    message: "[ai]      provider=anthropic · model=claude-sonnet-4-6" },
  { ts: "19:46:38.226", phase: "reporting",   level: "info",    message: "[safety]  8/8 outputs passed validator" },
  { ts: "19:46:54.502", phase: "completed",   level: "info",    message: "[done]    audit complete — 8 findings filed" },
];

export function ConsoleStream({ auditId }: { auditId?: string }) {
  const isDemo = !auditId || auditId === "demo";
  const [lines, setLines] = useState<Line[]>([]);
  const [conn, setConn] = useState<ConnState>("idle");
  const ref = useRef<HTMLDivElement>(null);

  // DEMO replay.
  useEffect(() => {
    if (!isDemo) return;
    let i = 0;
    setLines([DEMO_TAPE[0]]); i = 1;
    setConn("polling");
    const t = setInterval(() => {
      setLines((prev) => {
        if (i >= DEMO_TAPE.length) { setConn("done"); clearInterval(t); return prev; }
        return [...prev, DEMO_TAPE[i++]];
      });
    }, 360);
    return () => clearInterval(t);
  }, [isDemo]);

  // LIVE polling.
  useEffect(() => {
    if (isDemo || !auditId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cursor = 0;
    setConn("polling");

    const tick = async () => {
      if (cancelled) return;
      try {
        const r = await fetch(`/api/v1/audits/${auditId}/events.json?since=${cursor}`, { cache: "no-store" });
        if (!r.ok) throw new Error(String(r.status));
        const d = await r.json();
        if (cancelled) return;
        const events = (d.events || []) as Line[];
        if (events.length > 0) {
          setLines((prev) => [
            ...prev,
            ...events.map((e) => ({
              ...e,
              ts: typeof e.ts === "string" ? e.ts.slice(11, 23) : "--:--:--.---",
              message: neutralizeToolNames(String(e.message || "")),
            })),
          ]);
          cursor = events[events.length - 1].id ?? cursor;
        } else if (typeof d.cursor === "number" && d.cursor > cursor) {
          cursor = d.cursor;
        }
        if (d.state === "succeeded" || d.state === "failed") {
          setConn("done");
          return;
        }
      } catch {
        // transient — just retry next tick
      }
      timer = setTimeout(tick, POLL_MS);
    };

    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [isDemo, auditId]);

  // Autoscroll on new lines.
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [lines.length]);

  return (
    <div className="panel pt-4">
      <div className="flex items-baseline justify-between px-5 py-3 font-mono text-[11px]">
        <span className="text-bone-ghost uppercase tracking-widest2">/dev/audit/console</span>
        <ConnPill conn={conn} count={lines.length} />
      </div>

      <div ref={ref} className="max-h-[420px] min-h-[220px] overflow-y-auto border-t border-ink-300 px-5 py-3 font-mono text-[12px] leading-[20px]">
        {lines.length === 0 && (
          <div className="text-bone-mute">
            <span className="text-bone-ghost">//</span> awaiting first frame
            <span className="term-cursor" />
          </div>
        )}
        {lines.map((l, i) => (
          <div key={l.id ?? i} className="grid grid-cols-[80px_92px_120px_1fr] gap-3">
            <span className="text-ink-400 tabular">0x{i.toString(16).padStart(6, "0")}</span>
            <span className="text-bone-ghost tabular">{l.ts}</span>
            <span className={clsx("uppercase tracking-widest2 text-[10px]",
              l.level === "error" ? "text-signal-critical"
              : l.level === "warning" ? "text-signal-high"
              : "text-signal-live")}>[{l.phase}]</span>
            <span className={clsx("whitespace-pre-wrap",
              l.level === "error" ? "text-signal-critical"
              : l.level === "warning" ? "text-signal-high"
              : "text-bone-dim")}>{l.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConnPill({ conn, count }: { conn: ConnState; count: number }) {
  if (conn === "done")
    return <span className="text-bone-ghost uppercase tracking-widest2">stream closed · {count} frames</span>;
  if (conn === "error")
    return <span className="text-signal-critical uppercase tracking-widest2">stream interrupted</span>;
  if (conn === "polling")
    return <span className="text-signal-live uppercase tracking-widest2">streaming<span className="term-cursor" /> · {count}</span>;
  return <span className="text-bone-ghost uppercase tracking-widest2">idle</span>;
}
