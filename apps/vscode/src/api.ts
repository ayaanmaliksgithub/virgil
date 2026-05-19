/**
 * Tiny HTTP client for the Virgil API. Uses Node's built-in `fetch` (>= 18,
 * VS Code 1.85 ships Node 20.x in its extension host).
 *
 * Centralized so the extension code never assembles URLs ad-hoc and so we
 * have one place to handle the "API is down on localhost" failure mode —
 * the diagnostics provider treats those as "no findings" rather than
 * surfacing a popup every time the user moves the cursor.
 */
import type { Audit, Finding } from "./types";

export class ApiError extends Error {
  constructor(public status: number, detail = "") {
    super(`API ${status}${detail ? `: ${detail}` : ""}`);
    this.name = "ApiError";
  }
}

export class ApiUnreachable extends Error {
  constructor(cause?: unknown) {
    super(`API unreachable: ${(cause as Error)?.message ?? String(cause)}`);
    this.name = "ApiUnreachable";
  }
}

async function request<T>(base: string, path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(base.replace(/\/+$/, "") + path, {
      ...init,
      headers: { accept: "application/json", ...(init?.headers ?? {}) },
    });
  } catch (e) {
    throw new ApiUnreachable(e);
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new ApiError(res.status, detail.slice(0, 500));
  }
  return (await res.json()) as T;
}

export async function getAudit(base: string, id: string): Promise<Audit> {
  return request<Audit>(base, `/v1/audits/${encodeURIComponent(id)}`);
}

export interface ListFindingsOpts {
  includeSuppressed?: boolean;
}

export async function listFindings(
  base: string,
  auditId: string,
  opts: ListFindingsOpts = {}
): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (opts.includeSuppressed) params.set("include_suppressed", "true");
  const qs = params.toString();
  const body = await request<{ items: Finding[] }>(
    base,
    `/v1/audits/${encodeURIComponent(auditId)}/findings${qs ? `?${qs}` : ""}`
  );
  return body.items;
}
