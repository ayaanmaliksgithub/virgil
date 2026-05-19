/**
 * Subset of the Virgil API types the extension cares about.
 *
 * Kept narrow + duplicated rather than importing from the web app — the
 * extension is its own publishable artifact and shouldn't carry a path
 * dependency on `apps/web`. The types here only need the fields the
 * diagnostic mapper reads.
 */

export type Severity =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Informational";

export interface AffectedLine {
  file: string;
  start: number;
  end?: number | null;
}

export interface Finding {
  id: string;
  audit_id?: string;
  title: string;
  severity: Severity;
  confidence: string;
  category: string;
  owasp_category?: string | null;
  cwe?: string | null;
  cve?: string | null;
  affected_files: string[];
  affected_lines: AffectedLine[];
  evidence: string;
  explanation: string;
  business_impact?: string | null;
  safe_guidance?: string | null;
  source_tool: string[];
  status: string;
  kev?: boolean;
  reachable?: boolean | null;
  suppressed?: boolean;
  suppression_reason?: string | null;
}

export interface Audit {
  id: string;
  source_kind: "url" | "zip";
  source_ref: string;
  state: "pending" | "running" | "succeeded" | "failed";
  phase: string;
  created_at: string;
  finished_at?: string | null;
}
