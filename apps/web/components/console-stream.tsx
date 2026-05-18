"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";

/**
 * Two modes:
 *   - DEMO  (auditId === "demo" or unset) — replays a baked tape.
 *   - LIVE  (any other auditId)           — EventSource against
 *     /api/v1/audits/:id/events. Auto-reconnects with exponential backoff;
 *     closes cleanly on the server's `done` frame; surfaces connection state
 *     so the analyst doesn't stare at a frozen ledger.
 */

type Line = { ts: string; phase: string; level: "info" | "warning" | "error"; message: string };
type ConnState = "idle" | "connecting" | "open" | "done" | "error";

const DEMO_TAPE: Line[] = [
  { ts: "19:42:08.114", phase: "cloning",     level: "info",    message: "[sandbox] provisioning virgil/scanner:latest" },
  { ts: "19:42:09.812", phase: "cloning",     level: "info",    message: "[git]     clone --depth=1 --no-tags https://github.com/owasp/nodegoat" },
  { ts: "19:42:21.336", phase: "cloning",     level: "info",    message: "[git]     HEAD = 9f3c1d8" },
  { ts: "19:42:22.901", phase: "analyzing",   level: "info",    message: "[profile] lang=js(142) ts(38) · pkg=npm · fw=express · iac=docker,gha" },
  { ts: "19:42:24.180", phase: "scanning",    level: "info",    message: "[semgrep] config=p/owasp-top-ten,p/security-audit,p/secrets · timeout=120" },
  { ts: "19:43:48.044", phase: "scanning",    level: "info",    message: "[semgrep] rc=0 · raw=14" },
  { ts: "19:43:49.211", phase: "scanning",    level: "info",    message: "[trivy]   fs --scanners=vuln,misconfig,secret · timeout=300" },
  { ts: "19:45:01.778", phase: "scanning",    level: "warning", message: "[trivy]   1 misconfig source unresolved (continuing)" },
  { ts: "19:45:02.013", phase: "scanning",    level: "info",    message: "[gitleak] detect --no-git --redact" },
  { ts: "19:45:11.612", phase: "correlating", level: "info",    message: "[norm]    raw=27 → unified=8" },
  { ts: "19:45:12.119", phase: "correlating", level: "info",    message: "[norm]    agreement=2 · conf bumped → HI" },
  { ts: "19:45:13.040", phase: "reporting",   level: "info",    message: "[ai]      provider=anthropic · model=claude-opus-4-7" },
  { ts: "19:46:38.226", phase: "reporting",   level: "info",    message: "[safety]  8/8 outputs passed validator" },
  { ts: "19:46:54.502", phase: "completed",   level: "info",    message: "[done]    audit complete — 8 findings filed" },
];

export function ConsoleStream({ auditId }: { auditId?: string }) {
  const isDemo = !auditId || auditId === "demo";
  const [lines, setLines] = useState<Line[]>([]);
  const [conn, setConn] = useState<ConnState>("idle");
  const ref = useRef<HTMLDivElement>(null);

  // DEMO replay
  useEffect(() => {
    if (!isDemo) return;
    let i = 0;
    setLines([DEMO_TAPE[0]]); i = 1;
    setConn("open");
    const t = setInterval(() => {
      setLines((prev) => {
        if (i >= DEMO_TAPE.length) { setConn("done"); clearInterval(t); return prev; }
        return [...prev, DEMO_TAPE[i++]];
      });
    }, 360);
    return () => clearInterval(t);
  }, [isDemo]);

  // LIVE SSE
  useEffect(() => {
    if (isDemo || !auditId) return;
    let cancelled = false;
    let backoffMs = 1000;
    let es: EventSource | null = null;

    const connect = () => {
      if (cancelled) return;
      setConn("connecting");
      es = new EventSource(`/api/v1/audits/${auditId}/events`);

      es.addEventListener("log", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data);
          const ts = (data.ts || "").slice(11, 23) || "--:--:--.---";
          setLines((prev) => [
            ...prev,
            {
              ts,
              phase: String(data.phase ?? "?"),
              level: (data.level ?? "info") as Line["level"],
              message: String(data.message ?? ""),
            },
          ]);
        } catch { /* malformed frame */ }
      });

      es.addEventListener("done", () => { setConn("done"); es?.close(); });

      es.onopen = () => { setConn("open"); backoffMs = 1000; };
      es.onerror = () => {
        setConn("error");
        es?.close();
        if (cancelled) return;
        const delay = Math.min(backoffMs, 10_000);
        backoffMs = Math.min(backoffMs * 2, 10_000);
        setTimeout(connect, delay);
      };
    };

    connect();
    return () => { cancelled = true; es?.close(); };
  }, [isDemo, auditId]);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  const status = useMemo(() => {
    if (conn === "open")       return { dot: "text-signal-live",     label: isDemo ? "demo · tape replay" : "tail -f /dev/audit/console" };
    if (conn === "connecting") return { dot: "text-signal-high",     label: "connecting…" };
    if (conn === "done")       return { dot: "text-bone-mute",       label: "stream closed · audit complete" };
    if (conn === "error")      return { dot: "text-signal-critical", label: "connection lost · retrying" };
    return                          { dot: "text-bone-ghost",        label: "idle" };
  }, [conn, isDemo]);

  return (
    <div className="panel pt-4">
      <span className="panel-title">/dev/audit/console</span>

      <div className="flex items-center justify-between border-b border-ink-300 bg-ink px-4 py-2 font-mono text-[10px] uppercase tracking-widest2">
        <div className="flex items-center gap-3 text-bone-mute">
          <span className={status.dot}>●</span> {status.label}
        </div>
        <span className="text-bone-ghost tabular">
          frames {lines.length.toString().padStart(3, "0")}
        </span>
      </div>

      <div
        ref={ref}
        className="max-h-[440px] overflow-y-auto py-2 font-mono text-[12px] leading-[20px]"
      >
        {lines.map((l, i) => (
          <div
            key={i}
            className="grid grid-cols-[80px_92px_84px_1fr] gap-3 px-4 py-[1px] hover:bg-ink-100"
          >
            <span className="text-ink-400 tabular">
              0x{(i * 0x10).toString(16).padStart(6, "0")}
            </span>
            <span className="text-bone-ghost tabular">{l.ts}</span>
            <span
              className={clsx(
                "uppercase tracking-widest2",
                l.level === "warning" ? "text-signal-high" :
                l.level === "error" ? "text-signal-critical" :
                "text-bone-mute"
              )}
            >
              [{l.phase}]
            </span>
            <span
              className={clsx(
                l.level === "warning" ? "text-signal-high" :
                l.level === "error" ? "text-signal-critical" :
                "text-bone-dim"
              )}
            >
              {l.message}
            </span>
          </div>
        ))}
        <div className="grid grid-cols-[80px_92px_84px_1fr] gap-3 px-4 py-[1px]">
          <span className="text-ink-400 tabular">
            0x{(lines.length * 0x10).toString(16).padStart(6, "0")}
          </span>
          <span className="text-bone-ghost tabular">--:--:--.---</span>
          <span
            className={clsx(
              "uppercase tracking-widest2",
              conn === "done"  ? "text-bone-mute" :
              conn === "error" ? "text-signal-critical" :
              "text-bone-ghost"
            )}
          >
            [{conn === "done" ? "halt" : conn === "error" ? "retry" : "wait"}]
          </span>
          <span className="text-bone-fog">
            {conn === "done" ? "stream closed" : conn === "error" ? "reconnecting" : "awaiting next frame"}
            {conn === "open" || conn === "connecting" ? <span className="term-cursor" /> : null}
          </span>
        </div>
      </div>
    </div>
  );
}
