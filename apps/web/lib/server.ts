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
 * UUID of the OWASP NodeGoat demo audit that `app.seed` loads on a fresh DB.
 * Stable so the frontend can link to it without round-tripping the API.
 */
export const SEED_DEMO_AUDIT_ID = "00000000-0000-0000-0000-000000000001";

/**
 * Pick the right demo target for the landing page.
 *
 * If the API has the seeded demo audit, link to the real DB-backed
 * `/audits/<uuid>` so the user gets the full backend (chat, report routes,
 * exports). If the API is down or the seed was disabled, fall back to the
 * frontend-only `/audits/demo` route which renders against `lib/demo.ts`.
 *
 * Best-effort: a hung API on a homepage render shouldn't 500 the landing.
 */
export async function resolveDemoAuditHref(): Promise<string> {
  try {
    await getAudit(SEED_DEMO_AUDIT_ID);
    return `/audits/${SEED_DEMO_AUDIT_ID}`;
  } catch {
    return "/audits/demo";
  }
}

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
