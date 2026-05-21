/**
 * Maps internal scanner adapter names to vendor-neutral, user-facing labels.
 *
 * Backend findings carry `source_tool` like "semgrep" / "trivy" / "gitleaks";
 * the UI never shows those raw names. This helper is the single source of
 * truth for the substitution.
 */
const TOOL_LABEL: Record<string, string> = {
  semgrep: "static analysis",
  trivy: "dependency scan",
  gitleaks: "secret scan",
  codeql: "deep analysis",
};

const TOOL_TAG: Record<string, string> = {
  semgrep: "static",
  trivy: "deps",
  gitleaks: "secrets",
  gitleak: "secrets",
  codeql: "deepstatic",
};

export function friendlyToolName(name: string | undefined | null): string {
  if (!name) return "scanner";
  return TOOL_LABEL[name.toLowerCase()] ?? "scanner";
}

export function friendlyToolTag(name: string | undefined | null): string {
  if (!name) return "engine";
  return TOOL_TAG[name.toLowerCase()] ?? "engine";
}

/**
 * Strip vendor names from a free-form log/console line. Used to scrub live
 * SSE messages that come pre-formatted from the worker (e.g. "semgrep
 * finished rc=1" or "[trivy] ...").
 */
export function neutralizeToolNames(msg: string): string {
  if (!msg) return msg;
  return msg.replace(/\b(semgrep|trivy|gitleaks?|codeql)\b/gi, (m) =>
    TOOL_TAG[m.toLowerCase()] ?? "engine"
  );
}
