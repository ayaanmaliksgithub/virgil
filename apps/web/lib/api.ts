/**
 * Thin API client. Routes go through Next's rewrite at /api/* → FastAPI.
 * Demo mode kicks in when audit_id === "demo" so every page renders without
 * a running backend — useful for design review.
 */
import type { Finding, Audit, ChatResponse, ReportPayload } from "./types";
import { DEMO_AUDIT, DEMO_FINDINGS, DEMO_REPORT, demoChat } from "./demo";

// Browser: hit Next.js, which rewrites /api/* to the FastAPI base.
// SSR (node): Next rewrites do not apply to internal fetch(); use the api host directly.
const BASE = typeof window === "undefined"
  ? (process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000")
  : "/api";

export class ApiError extends Error {
  constructor(public status: number, public detail?: string) {
    super(detail || `HTTP ${status}`);
    this.name = "ApiError";
  }
}

export class ApiUnreachable extends Error {
  constructor(cause?: unknown) {
    super("backend unreachable");
    this.name = "ApiUnreachable";
    if (cause instanceof Error) this.stack = cause.stack;
  }
}

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers || {}) },
      cache: "no-store",
    });
  } catch (e) {
    // fetch only rejects on network failure — DNS, refused, aborted.
    throw new ApiUnreachable(e);
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export async function getAudit(id: string): Promise<Audit> {
  if (id === "demo") return DEMO_AUDIT;
  return http<Audit>(`/v1/audits/${id}`);
}

export interface QueueStatus {
  state: "pending" | "running" | "succeeded" | "failed";
  phase: string;
  active: boolean;
  position?: number;
  ahead?: number;
  in_flight?: number;
}

export async function getQueueStatus(id: string): Promise<QueueStatus> {
  if (id === "demo") {
    // Demo flow: pretend we just submitted and there are two audits ahead.
    return { state: "pending", phase: "queued", active: true, position: 3, ahead: 2, in_flight: 1 };
  }
  return http<QueueStatus>(`/v1/audits/${id}/queue`);
}

export interface ListFindingsOptions {
  includeSuppressed?: boolean;
  lifecycle?: ("new" | "recurring" | "resolved")[];
  baseline?: string;
}

export async function listFindings(
  id: string,
  opts: ListFindingsOptions = {}
): Promise<{ items: Finding[]; baseline_audit_id?: string | null }> {
  if (id === "demo") return { items: DEMO_FINDINGS };
  const params = new URLSearchParams();
  if (opts.includeSuppressed) params.set("include_suppressed", "true");
  if (opts.lifecycle?.length) opts.lifecycle.forEach((l) => params.append("lifecycle", l));
  if (opts.baseline) params.set("baseline", opts.baseline);
  const qs = params.toString();
  return http<{ items: Finding[]; baseline_audit_id?: string | null }>(
    `/v1/audits/${id}/findings${qs ? `?${qs}` : ""}`
  );
}

export interface SuppressionPayload {
  dedupe_key: string;
  reason: string;
  actor?: string | null;
  expires_at?: string | null;
}

export async function createSuppression(auditId: string, body: SuppressionPayload) {
  if (auditId === "demo") return { id: "demo-suppression", ...body };
  return http(`/v1/audits/${auditId}/suppressions`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function deleteSuppression(suppressionId: string): Promise<void> {
  if (suppressionId === "demo-suppression") return;
  const res = await fetch(`${BASE}/v1/suppressions/${suppressionId}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new ApiError(res.status, await res.text().catch(() => ""));
}

export interface ClusterHint {
  shared_dir: string | null;
  shared_modules: string[];
}

export interface Cluster {
  key: string;
  category: string;
  cwe: string | null;
  rule_signature: string;
  title: string;
  severity: import("./types").Severity;
  confidence: string;
  instances: number;
  files: string[];
  cves: string[];
  kev: boolean;
  any_unreachable: boolean;
  all_unreachable: boolean;
  representative_id: string;
  finding_ids: string[];
  hint?: ClusterHint;
}

export async function listClusters(
  auditId: string,
  opts: { includeUnreachable?: boolean } = {}
): Promise<{ items: Cluster[]; total_findings: number; total_clusters: number }> {
  if (auditId === "demo") {
    // Cheap demo: synthesize clusters from the demo findings.
    const { DEMO_FINDINGS } = await import("./demo");
    const map = new Map<string, Cluster>();
    DEMO_FINDINGS.forEach((f) => {
      const k = `${f.category}|${f.cwe ?? "-"}`;
      const existing = map.get(k);
      if (existing) {
        existing.instances += 1;
        existing.files = Array.from(new Set([...existing.files, ...f.affected_files])).slice(0, 12);
      } else {
        map.set(k, {
          key: k,
          category: f.category,
          cwe: f.cwe ?? null,
          rule_signature: `demo:${f.category}`,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          instances: 1,
          files: [...f.affected_files].slice(0, 12),
          cves: f.cve ? [f.cve] : [],
          kev: !!f.kev,
          any_unreachable: f.reachable === false,
          all_unreachable: f.reachable === false,
          representative_id: f.id,
          finding_ids: [f.id],
        });
      }
    });
    return { items: Array.from(map.values()), total_findings: DEMO_FINDINGS.length, total_clusters: map.size };
  }
  const params = new URLSearchParams();
  if (opts.includeUnreachable) params.set("include_unreachable", "true");
  const qs = params.toString();
  return http(`/v1/audits/${auditId}/findings/clusters${qs ? `?${qs}` : ""}`);
}

export interface SuggestedQuestion {
  label: string;
  prompt: string;
}

export async function getSuggestedQuestions(
  auditId: string
): Promise<SuggestedQuestion[]> {
  if (auditId === "demo") {
    return [
      { label: "where to start?", prompt: "Given everything in this audit, where should I spend my first hour and why?" },
      { label: "is this dep used?", prompt: "How is the lodash package actually used in this codebase, and which call sites are at risk?" },
      { label: "secret rotation scope?", prompt: "What's the rotation scope for the AWS key finding — only this credential or related services?" },
    ];
  }
  const res = await http<{ items: SuggestedQuestion[] }>(`/v1/audits/${auditId}/chat/suggested`);
  return res.items;
}

export async function setBaseline(
  auditId: string,
  baselineAuditId: string | null
): Promise<{ audit_id: string; baseline_audit_id: string | null }> {
  if (auditId === "demo") return { audit_id: auditId, baseline_audit_id: baselineAuditId };
  return http(`/v1/audits/${auditId}/baseline`, {
    method: "PATCH",
    body: JSON.stringify({ baseline_audit_id: baselineAuditId }),
  });
}

export async function getFinding(id: string, fid: string): Promise<Finding | undefined> {
  if (id === "demo") return DEMO_FINDINGS.find((f) => f.id === fid);
  return http<Finding>(`/v1/findings/${fid}`);
}

export async function getReport(
  id: string,
  view: "executive" | "technical" = "technical"
): Promise<ReportPayload> {
  if (id === "demo") return DEMO_REPORT[view];
  return http<ReportPayload>(`/v1/audits/${id}/report?view=${view}&format=json`);
}

export async function submitUrl(repo_url: string, github_token?: string): Promise<Audit> {
  const body: Record<string, string> = { repo_url };
  if (github_token) body.github_token = github_token;
  const res = await fetch(BASE + "/v1/audits/json", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
}

export async function submitZip(file: File): Promise<Audit> {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch(BASE + "/v1/audits", { method: "POST", body: fd });
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
  return res.json();
}

export async function postChat(
  auditId: string,
  message: string,
  sessionId?: string
): Promise<ChatResponse> {
  if (auditId === "demo") return demoChat(message, sessionId);
  return http<ChatResponse>(`/v1/audits/${auditId}/chat`, {
    method: "POST",
    body: JSON.stringify({ message, session_id: sessionId ?? null }),
  });
}

/**
 * Stream a chat answer via Server-Sent Events.
 *
 * Frame schedule (mirrors the backend route):
 *   `session` → { session_id }                 — once, up front
 *   `token`   → { text }                       — many; incremental answer text
 *   `done`    → { message, history, refused }  — once, at the end
 *   `error`   → { detail }                     — only on failure
 *
 * Demo mode degrades to the non-streaming path and replays the whole answer
 * as a single token frame so the UI logic stays unified.
 *
 * Returns an `{ cancel }` handle that aborts the underlying fetch when called
 * — e.g. when the component unmounts mid-stream.
 */
export interface StreamChatHandlers {
  onSession?: (sessionId: string) => void;
  onToken: (text: string) => void;
  onDone: (payload: ChatResponse & { refused: boolean }) => void;
  onError: (detail: string) => void;
}

export interface StreamChatHandle {
  cancel: () => void;
}

export function streamChat(
  auditId: string,
  message: string,
  sessionId: string | undefined,
  handlers: StreamChatHandlers
): StreamChatHandle {
  if (auditId === "demo") {
    let cancelled = false;
    demoChat(message, sessionId).then((res) => {
      if (cancelled) return;
      handlers.onSession?.(res.session_id);
      handlers.onToken(res.message.content);
      handlers.onDone({ ...res, refused: false });
    }).catch((e) => { if (!cancelled) handlers.onError(e?.message || "demo chat error"); });
    return { cancel: () => { cancelled = true; } };
  }

  const controller = new AbortController();
  (async () => {
    let res: Response;
    try {
      res = await fetch(`${BASE}/v1/audits/${auditId}/chat/stream`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "text/event-stream" },
        body: JSON.stringify({ message, session_id: sessionId ?? null }),
        signal: controller.signal,
      });
    } catch (e) {
      if ((e as Error)?.name !== "AbortError") {
        handlers.onError("backend unreachable");
      }
      return;
    }
    if (!res.ok || !res.body) {
      const detail = await res.text().catch(() => "");
      handlers.onError(detail || `HTTP ${res.status}`);
      return;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        // SSE frames are separated by blank lines. Process complete frames only.
        let sep: number;
        while ((sep = buf.indexOf("\n\n")) >= 0) {
          const frame = buf.slice(0, sep);
          buf = buf.slice(sep + 2);
          dispatchFrame(frame, handlers);
        }
      }
      // Flush any trailing frame.
      if (buf.trim().length > 0) dispatchFrame(buf, handlers);
    } catch (e) {
      if ((e as Error)?.name !== "AbortError") {
        handlers.onError("stream interrupted");
      }
    }
  })();

  return { cancel: () => controller.abort() };
}

function dispatchFrame(frame: string, handlers: StreamChatHandlers) {
  // Each frame is a sequence of `field: value` lines. We only care about
  // `event` and `data`. Comments (`:`) are ignored. Multi-line `data:` blocks
  // are concatenated with `\n` per the SSE spec.
  let eventName = "message";
  const dataLines: string[] = [];
  for (const line of frame.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    if (line.startsWith("event:")) eventName = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
  }
  if (dataLines.length === 0) return;
  let payload: any;
  try { payload = JSON.parse(dataLines.join("\n")); }
  catch { return; }

  if (eventName === "session" && payload?.session_id) handlers.onSession?.(payload.session_id);
  else if (eventName === "token" && typeof payload?.text === "string") handlers.onToken(payload.text);
  else if (eventName === "done") {
    handlers.onDone({
      session_id: payload?.message?.session_id ?? "",  // backend uses the session frame for id
      message: payload.message,
      history: payload.history,
      refused: !!payload.refused,
    } as ChatResponse & { refused: boolean });
  }
  else if (eventName === "error") handlers.onError(payload?.detail || "chat error");
}
