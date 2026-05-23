/**
 * Subset of the Virgil API shape that crosses the CLI ↔ extension boundary.
 *
 * The CLI emits these as JSON (see `apps/cli/cli/main.py` — every `--json`
 * subcommand passes the API's response through verbatim). Kept narrow and
 * duplicated here rather than imported from `apps/web` so the extension stays
 * an independent publishable artifact.
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
