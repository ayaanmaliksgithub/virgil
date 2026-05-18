export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type Confidence =
  | "High confidence"
  | "Medium confidence"
  | "Low confidence"
  | "Requires manual verification";
export type Phase =
  | "queued" | "cloning" | "analyzing" | "scanning" | "correlating"
  | "reporting" | "completed" | "failed";

export interface AffectedLine { file: string; start: number; end?: number | null; }

export type Lifecycle = "new" | "recurring" | "resolved";

export interface Finding {
  id: string;
  audit_id?: string;
  dedupe_key?: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  owasp_category?: string | null;
  cwe?: string | null;
  cve?: string | null;
  affected_files: string[];
  affected_lines: AffectedLine[];
  evidence: string;
  explanation: string;
  exploitability_summary?: string | null;
  business_impact?: string | null;
  safe_guidance?: string | null;
  source_tool: string[];
  status: string;
  lifecycle?: Lifecycle | null;
  suppressed?: boolean;
  suppression_reason?: string | null;
  suppression_id?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  kev?: boolean;
  compliance?: Record<string, string[]>;
  reachable?: boolean | null;
  code_context?: string | null;
  created_at: string;
}

export interface Audit {
  id: string;
  source_kind: "url" | "zip";
  source_ref: string;
  state: "pending" | "running" | "succeeded" | "failed";
  phase: Phase;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  baseline_audit_id?: string | null;
  profile?: {
    languages?: Record<string, number>;
    package_managers?: string[];
    frameworks?: string[];
    iac?: string[];
    loc?: number;
    file_count?: number;
    narrative?: string;
    priority_list?: { cluster_key: string; reason: string }[];
  } | null;
}

export interface ChatTurn {
  id: string;
  role: "user" | "assistant";
  content: string;
  citations: string[];
  created_at: string;
}

export interface ChatResponse {
  session_id: string;
  message: ChatTurn;
  history: ChatTurn[];
}

export interface ReportPayload {
  audit_id: string;
  source: { kind: string; ref: string; sha?: string | null };
  generated_at?: string | null;
  summary: {
    total_findings: number;
    severity_breakdown: Record<Severity, number>;
    category_breakdown?: Record<string, number>;
    owasp_breakdown?: Record<string, number>;
  };
  narrative?: string;
  top_findings?: {
    title: string; severity: Severity; category: string;
    owasp_category?: string | null; business_impact?: string | null;
  }[];
  findings?: Finding[];
  profile?: Audit["profile"];
}
