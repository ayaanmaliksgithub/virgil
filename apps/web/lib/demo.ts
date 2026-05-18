/**
 * Demo fixture for /audits/demo/* — lets the design be reviewed without the
 * worker running. Numbers and titles are illustrative, not real findings.
 */
import type { Audit, ChatResponse, ChatTurn, Finding, ReportPayload } from "./types";

export const DEMO_AUDIT: Audit = {
  id: "demo",
  source_kind: "url",
  source_ref: "https://github.com/OWASP/NodeGoat",
  state: "succeeded",
  phase: "completed",
  created_at: "2026-05-15T19:42:00Z",
  started_at: "2026-05-15T19:42:08Z",
  finished_at: "2026-05-15T19:46:54Z",
  profile: {
    languages: { JavaScript: 142, TypeScript: 38, Shell: 6, YAML: 11 },
    package_managers: ["npm"],
    frameworks: ["Express"],
    iac: ["Dockerfile", "GitHub Actions"],
    loc: 23_104,
    file_count: 412,
    narrative:
      "This codebase exposes a non-trivial credential surface alongside two injection-class vulnerabilities in user-controlled paths. Dependency hygiene is the dominant axis of risk — six third-party packages contribute most of the Critical/High volume. Authentication primitives are present but inconsistently applied across routes. No infrastructure-as-code drift was detected beyond a permissive Dockerfile baseline.",
  },
};

export const DEMO_FINDINGS: Finding[] = [
  {
    id: "f-001",
    audit_id: "demo",
    title: "Hardcoded AWS access key in source",
    severity: "Critical",
    confidence: "High confidence",
    category: "Secret Exposure",
    owasp_category: "A07:2021 - Identification and Authentication Failures",
    cwe: "CWE-798",
    cve: null,
    affected_files: ["app/data/config/aws.ts"],
    affected_lines: [{ file: "app/data/config/aws.ts", start: 14, end: 14 }],
    evidence: "const accessKey = \"AKIA****************\"",
    explanation:
      "A long-lived AWS access key is committed to the repository. Static credentials in source control are accessible to anyone with read access to the repo and persist in git history even after deletion.",
    exploitability_summary:
      "Possession of a valid access key permits actions against the associated account scoped to its IAM policy. Risk depends on attached permissions.",
    business_impact:
      "Potential unauthorized access to cloud resources, billing exposure, and data loss; severity depends on the role attached to the credential.",
    safe_guidance:
      "Rotate the credential, move secrets to a managed secret store, and add pre-commit secret scanning. Audit recent CloudTrail activity for the key.",
    source_tool: ["gitleaks", "trivy"],
    status: "open",
    created_at: "2026-05-15T19:45:12Z",
  },
  {
    id: "f-002",
    audit_id: "demo",
    title: "User-controlled query passed unsanitized to NoSQL driver",
    severity: "High",
    confidence: "Medium confidence",
    category: "Injection",
    owasp_category: "A03:2021 - Injection",
    cwe: "CWE-943",
    cve: null,
    affected_files: ["routes/profile.js"],
    affected_lines: [{ file: "routes/profile.js", start: 88, end: 96 }],
    evidence: "User.find({ email: req.body.email })",
    explanation:
      "A request body field flows directly into a MongoDB query selector without type coercion or schema validation, enabling operator-injection patterns.",
    exploitability_summary:
      "Risk depends on the surrounding authentication context. Manual verification recommended.",
    business_impact:
      "Account enumeration and authentication bypass are plausible if this query is exposed to unauthenticated callers.",
    safe_guidance:
      "Constrain the field to a string at the schema layer and reject unexpected operator shapes. Add explicit input validation on the route boundary.",
    source_tool: ["semgrep"],
    status: "open",
    created_at: "2026-05-15T19:45:13Z",
  },
  {
    id: "f-003",
    audit_id: "demo",
    title: "lodash@4.17.15 — Prototype pollution (CVE-2020-8203)",
    severity: "High",
    confidence: "High confidence",
    category: "Vulnerable Dependency",
    owasp_category: "A06:2021 - Vulnerable and Outdated Components",
    cwe: "CWE-1321",
    cve: "CVE-2020-8203",
    affected_files: ["package-lock.json"],
    affected_lines: [{ file: "package-lock.json", start: 1, end: 1 }],
    evidence: "lodash 4.17.15 → fixed in 4.17.20",
    explanation:
      "A direct dependency on lodash 4.17.15 is vulnerable to prototype pollution. Several downstream packages also pin to vulnerable ranges.",
    business_impact:
      "Prototype pollution can yield denial-of-service or property-confusion conditions depending on how application objects are constructed.",
    safe_guidance:
      "Upgrade lodash to a patched release line and re-resolve transitive dependents. Track via your SBOM workflow.",
    source_tool: ["trivy"],
    status: "open",
    created_at: "2026-05-15T19:45:13Z",
  },
  {
    id: "f-004",
    audit_id: "demo",
    title: "Express route without CSRF protection",
    severity: "Medium",
    confidence: "Medium confidence",
    category: "CSRF",
    owasp_category: "A01:2021 - Broken Access Control",
    cwe: "CWE-352",
    cve: null,
    affected_files: ["routes/contributions.js"],
    affected_lines: [{ file: "routes/contributions.js", start: 14, end: 21 }],
    evidence: "router.post('/contributions/', (req, res) => {",
    explanation:
      "A state-changing POST handler does not appear to be covered by the application's CSRF middleware.",
    business_impact:
      "Cross-site requests from a victim browser could trigger unintended state changes if a session cookie is present.",
    safe_guidance:
      "Apply CSRF protection consistently across all state-changing routes; centralize the middleware so coverage is verifiable.",
    source_tool: ["semgrep"],
    status: "open",
    created_at: "2026-05-15T19:45:14Z",
  },
  {
    id: "f-005",
    audit_id: "demo",
    title: "Permissive Dockerfile — runs as root",
    severity: "Medium",
    confidence: "High confidence",
    category: "Infrastructure / IaC Misconfiguration",
    owasp_category: "A05:2021 - Security Misconfiguration",
    cwe: null,
    cve: null,
    affected_files: ["Dockerfile"],
    affected_lines: [{ file: "Dockerfile", start: 1, end: 28 }],
    evidence: "FROM node:14\n# (no USER directive set)",
    explanation:
      "The image does not drop to a non-root user. A runtime process compromise gains root inside the container by default.",
    business_impact:
      "Expanded blast radius if the application is exploited at runtime, particularly when combined with kernel-level escapes.",
    safe_guidance:
      "Introduce a non-root user in the image and adopt a minimal base. Enforce via your CI policy and image scanner.",
    source_tool: ["trivy"],
    status: "open",
    created_at: "2026-05-15T19:45:14Z",
  },
  {
    id: "f-006",
    audit_id: "demo",
    title: "JWT signed with default HS256 secret string",
    severity: "High",
    confidence: "High confidence",
    category: "Cryptography",
    owasp_category: "A02:2021 - Cryptographic Failures",
    cwe: "CWE-321",
    cve: null,
    affected_files: ["app/auth/token.js"],
    affected_lines: [{ file: "app/auth/token.js", start: 22, end: 22 }],
    evidence: "jwt.sign(payload, \"changeme\")",
    explanation:
      "Token signing uses a low-entropy placeholder secret. Anyone who recovers the string can mint tokens with arbitrary claims.",
    business_impact:
      "Effective authentication bypass for any flow that trusts these tokens.",
    safe_guidance:
      "Rotate the signing key to a high-entropy value sourced from a secret manager, and shorten token lifetimes.",
    source_tool: ["gitleaks", "semgrep"],
    status: "open",
    created_at: "2026-05-15T19:45:15Z",
  },
  {
    id: "f-007",
    audit_id: "demo",
    title: "Open redirect via unvalidated `next` parameter",
    severity: "Low",
    confidence: "Medium confidence",
    category: "Open Redirect",
    owasp_category: "A01:2021 - Broken Access Control",
    cwe: "CWE-601",
    cve: null,
    affected_files: ["routes/login.js"],
    affected_lines: [{ file: "routes/login.js", start: 47, end: 51 }],
    evidence: "res.redirect(req.query.next)",
    explanation:
      "A redirect target is taken from a request parameter without an allowlist. Useful as a credential-phishing primitive when chained with social engineering.",
    business_impact:
      "Brand trust impact; can amplify phishing campaigns that abuse your domain.",
    safe_guidance:
      "Constrain redirect targets to an allowlist of internal paths and reject external schemes.",
    source_tool: ["semgrep"],
    status: "open",
    created_at: "2026-05-15T19:45:16Z",
  },
  {
    id: "f-008",
    audit_id: "demo",
    title: "Debug log emits full request body — risk of secret leakage",
    severity: "Informational",
    confidence: "Low confidence",
    category: "Code Quality / Security Smell",
    owasp_category: "A09:2021 - Security Logging and Monitoring Failures",
    cwe: null,
    cve: null,
    affected_files: ["middleware/log.js"],
    affected_lines: [{ file: "middleware/log.js", start: 9, end: 12 }],
    evidence: "console.log(req.body)",
    explanation:
      "Request bodies are logged verbatim. Sensitive fields will be persisted to your log pipeline.",
    business_impact:
      "Secondary exposure surface for any sensitive submitted field; affects retention/incident playbooks.",
    safe_guidance:
      "Redact known-sensitive fields before logging and forward through a structured logger with field filtering.",
    source_tool: ["semgrep"],
    status: "open",
    created_at: "2026-05-15T19:45:17Z",
  },
];

const SEVERITY_BREAKDOWN = DEMO_FINDINGS.reduce<Record<string, number>>((acc, f) => {
  acc[f.severity] = (acc[f.severity] || 0) + 1;
  return acc;
}, { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 });

const OWASP_BREAKDOWN = DEMO_FINDINGS.reduce<Record<string, number>>((acc, f) => {
  const k = f.owasp_category || "Unmapped";
  acc[k] = (acc[k] || 0) + 1;
  return acc;
}, {});

const CATEGORY_BREAKDOWN = DEMO_FINDINGS.reduce<Record<string, number>>((acc, f) => {
  acc[f.category] = (acc[f.category] || 0) + 1;
  return acc;
}, {});

export const DEMO_REPORT = {
  executive: {
    audit_id: "demo",
    source: { kind: "url", ref: DEMO_AUDIT.source_ref, sha: "9f3c1d8" },
    generated_at: DEMO_AUDIT.finished_at,
    summary: {
      total_findings: DEMO_FINDINGS.length,
      severity_breakdown: SEVERITY_BREAKDOWN as ReportPayload["summary"]["severity_breakdown"],
      owasp_breakdown: OWASP_BREAKDOWN,
    },
    narrative: DEMO_AUDIT.profile?.narrative,
    top_findings: DEMO_FINDINGS.slice(0, 5).map((f) => ({
      title: f.title,
      severity: f.severity,
      category: f.category,
      owasp_category: f.owasp_category,
      business_impact: f.business_impact,
    })),
  } as ReportPayload,
  technical: {
    audit_id: "demo",
    source: { kind: "url", ref: DEMO_AUDIT.source_ref, sha: "9f3c1d8" },
    generated_at: DEMO_AUDIT.finished_at,
    profile: DEMO_AUDIT.profile,
    summary: {
      total_findings: DEMO_FINDINGS.length,
      severity_breakdown: SEVERITY_BREAKDOWN as ReportPayload["summary"]["severity_breakdown"],
      owasp_breakdown: OWASP_BREAKDOWN,
      category_breakdown: CATEGORY_BREAKDOWN,
    },
    findings: DEMO_FINDINGS,
  } as ReportPayload,
};

// ---------------------------------------------------------------------------
// Demo chat — in-memory session keyed by session_id. The "answers" use simple
// keyword overlap against DEMO_FINDINGS and quote real evidence/explanations,
// so the UI can be reviewed without a real LLM call.
// ---------------------------------------------------------------------------

const _sessions: Map<string, ChatTurn[]> = new Map();

function _newId() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : "xxxxxxxxxxxx4xxx".replace(/x/g, () => Math.floor(Math.random() * 16).toString(16));
}

function _retrieve(query: string, k = 3): Finding[] {
  const terms = new Set(
    query.toLowerCase().match(/[a-z][a-z0-9_-]{2,}/g) || []
  );
  if (!terms.size) return DEMO_FINDINGS.slice(0, k);
  const scored = DEMO_FINDINGS.map((f) => {
    const hay = [
      f.title, f.category, f.owasp_category, f.cwe, f.cve,
      ...f.affected_files, f.explanation, f.business_impact,
    ].filter(Boolean).join(" ").toLowerCase();
    const hayTerms = new Set(hay.match(/[a-z][a-z0-9_-]{2,}/g) || []);
    let overlap = 0;
    terms.forEach((t) => { if (hayTerms.has(t)) overlap++; });
    return [overlap, f] as const;
  }).filter(([n]) => n > 0)
    .sort((a, b) => b[0] - a[0]);
  return scored.slice(0, k).map(([, f]) => f);
}

export function demoChat(message: string, sessionId?: string): Promise<ChatResponse> {
  const sid = sessionId && _sessions.has(sessionId) ? sessionId : _newId();
  const history = _sessions.get(sid) ?? [];

  const userTurn: ChatTurn = {
    id: _newId(), role: "user", content: message,
    citations: [], created_at: new Date().toISOString(),
  };

  const matched = _retrieve(message);
  let answer: string;
  let citations: string[];
  if (matched.length === 0) {
    answer =
      "I can't answer that from this audit's evidence. I'm bound to the stored findings and won't produce exploit-shaped content. Try asking about a specific finding, category, or affected file.";
    citations = [];
  } else {
    const top = matched[0];
    const bullets = matched
      .slice(0, 3)
      .map((f) => `- ${f.title} (${f.severity}) · ${f.category}`)
      .join("\n");
    answer =
      `Grounded in ${matched.length} finding${matched.length === 1 ? "" : "s"}:\n\n` +
      `${bullets}\n\n` +
      `Most relevant — ${top.title}. ${top.explanation} ` +
      `${top.business_impact ?? ""} Defensive guidance: ${top.safe_guidance ?? "—"}`;
    citations = matched.map((f) => f.id);
  }

  const assistantTurn: ChatTurn = {
    id: _newId(), role: "assistant", content: answer, citations,
    created_at: new Date().toISOString(),
  };

  const next = [...history, userTurn, assistantTurn];
  _sessions.set(sid, next);

  // Simulate a brief network/LLM latency so the UI's "thinking" state can be reviewed.
  return new Promise((resolve) =>
    setTimeout(
      () => resolve({ session_id: sid, message: assistantTurn, history: next }),
      450
    )
  );
}
