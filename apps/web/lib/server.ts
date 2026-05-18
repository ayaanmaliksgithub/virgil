/**
 * Server-side data-fetch helpers that translate API errors into Next's
 * `notFound()` flow and let everything else (5xx, network unreachable) hit
 * the route's `error.tsx` boundary.
 *
 * Keeping the translation in one place means individual page components don't
 * each have to remember the right pattern.
 */
import { notFound } from "next/navigation";
import { ApiError, getAudit, listFindings, getFinding, getQueueStatus, getReport, type ListFindingsOptions, type QueueStatus } from "./api";
import type { Audit, Finding, ReportPayload } from "./types";

export async function loadAudit(id: string): Promise<Audit> {
  try {
    return await getAudit(id);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}

/**
 * The repo offered as the one-click "try it" CTA on the homepage. Defaults
 * to OWASP NodeGoat — a deliberately-vulnerable Node.js training app with
 * publicly documented findings. Operators can override at build time via
 * `NEXT_PUBLIC_DEMO_SCAN_URL`.
 */
export const DEMO_SCAN_URL =
  process.env.NEXT_PUBLIC_DEMO_SCAN_URL || "https://github.com/OWASP/NodeGoat";

export async function loadFindings(
  id: string,
  opts: ListFindingsOptions = {}
): Promise<{ items: Finding[]; baseline_audit_id?: string | null }> {
  try {
    return await listFindings(id, opts);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}

export async function loadFinding(id: string, fid: string): Promise<Finding> {
  try {
    const f = await getFinding(id, fid);
    if (!f) notFound();
    return f;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}

export async function loadQueueStatus(id: string): Promise<QueueStatus | null> {
  // Best-effort: a backend that doesn't yet expose /queue (older deploy) or a
  // transient failure should NOT take the audit console down. The client-side
  // QueueBanner polls and will catch up on its own.
  try {
    return await getQueueStatus(id);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    return null;
  }
}


export async function loadReport(
  id: string,
  view: "executive" | "technical"
): Promise<ReportPayload> {
  try {
    return await getReport(id, view);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound();
    throw e;
  }
}
