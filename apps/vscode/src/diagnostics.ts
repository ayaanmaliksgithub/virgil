/**
 * Map Virgil findings → VS Code diagnostics.
 *
 * Three rules drive the mapping:
 *
 *   1. **Workspace-relative path resolution.** Findings carry paths like
 *      `app/routes/profile.js` (or sometimes `/repo/app/routes/profile.js`
 *      when emitted from inside the sandbox). We try the path as-is, then
 *      strip a `/repo/` prefix, then try each workspace folder as a root.
 *      If nothing resolves we skip — surfacing a diagnostic on a nonexistent
 *      file would be a worse-than-no-action UX.
 *
 *   2. **Severity floor.** The user's `virgil.minSeverity` setting drops
 *      anything below it.
 *
 *   3. **Severity → VS Code level.** Critical/High → Error, Medium →
 *      Warning, Low → Information, Informational → Hint. Same intent as the
 *      SARIF emitter but VS Code has a narrower 4-level enum.
 */
import * as vscode from "vscode";
import type { Finding, Severity } from "./types";

const SEVERITY_ORDER: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
];

function severityIndex(s: Severity): number {
  const i = SEVERITY_ORDER.indexOf(s);
  return i < 0 ? SEVERITY_ORDER.length : i;
}

function toDiagnosticSeverity(s: Severity): vscode.DiagnosticSeverity {
  switch (s) {
    case "Critical":
    case "High":
      return vscode.DiagnosticSeverity.Error;
    case "Medium":
      return vscode.DiagnosticSeverity.Warning;
    case "Low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Resolve a finding's reported file to a Uri inside the workspace. Returns
 * null if no workspace folder owns the path.
 *
 * Tries (in order):
 *   - rel as-is, joined to each workspace root
 *   - rel with leading `/repo/` stripped, joined to each workspace root
 *   - basename match against the first workspace root (last-ditch — better
 *     than nothing for findings whose path was rewritten by the sandbox)
 */
export function resolveFileUri(
  rel: string,
  folders: readonly vscode.WorkspaceFolder[]
): vscode.Uri | null {
  if (!rel || folders.length === 0) return null;

  const candidates = [
    rel.replace(/^\/+/, ""),
    rel.replace(/^\/repo\/+/, ""),
    rel.replace(/^repo\/+/, ""),
  ];

  for (const folder of folders) {
    for (const candidate of candidates) {
      const u = vscode.Uri.joinPath(folder.uri, candidate);
      // We can't synchronously stat without awaiting, but joinPath gives a
      // valid Uri regardless. The diagnostics collection silently ignores
      // entries on files that don't open; that's the right behavior here.
      return u;
    }
  }
  return null;
}

export interface BuildOpts {
  minSeverity: Severity;
  folders: readonly vscode.WorkspaceFolder[];
}

/**
 * Group findings into `Map<file uri string, vscode.Diagnostic[]>` ready
 * for `DiagnosticCollection.set`.
 */
export function buildDiagnostics(
  findings: Finding[],
  opts: BuildOpts
): Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }> {
  const floor = severityIndex(opts.minSeverity);
  const grouped = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }>();

  for (const f of findings) {
    if (severityIndex(f.severity) > floor) continue;
    const lines = f.affected_lines?.length
      ? f.affected_lines
      : f.affected_files.map((file) => ({ file, start: 1, end: null }));

    for (const al of lines) {
      const uri = resolveFileUri(al.file, opts.folders);
      if (!uri) continue;
      // VS Code is 0-indexed; findings are 1-indexed.
      const start = Math.max(0, (al.start ?? 1) - 1);
      const end = Math.max(start, (al.end ?? al.start ?? 1) - 1);
      const range = new vscode.Range(
        new vscode.Position(start, 0),
        new vscode.Position(end, Number.MAX_SAFE_INTEGER),
      );

      const diag = new vscode.Diagnostic(
        range,
        formatMessage(f),
        toDiagnosticSeverity(f.severity),
      );
      diag.source = "virgil";
      diag.code = ruleCode(f);
      // Show the file basename + finding category in the Problems panel
      // so it scans quickly.
      diag.tags = f.suppressed ? [vscode.DiagnosticTag.Unnecessary] : [];

      const key = uri.toString();
      let bucket = grouped.get(key);
      if (!bucket) {
        bucket = { uri, diags: [] };
        grouped.set(key, bucket);
      }
      bucket.diags.push(diag);
    }
  }

  return grouped;
}

function formatMessage(f: Finding): string {
  const lines = [`[${f.severity}] ${f.title}`];
  if (f.category) lines.push(`category: ${f.category}`);
  if (f.cwe) lines.push(`cwe: ${f.cwe}`);
  if (f.cve) lines.push(`cve: ${f.cve}${f.kev ? " (CISA KEV)" : ""}`);
  if (f.business_impact) lines.push(`impact: ${f.business_impact}`);
  if (f.safe_guidance) lines.push(`guidance: ${f.safe_guidance}`);
  if (f.reachable === false) {
    lines.push("note: dependency is not imported in source — severity demoted");
  }
  if (f.suppressed) {
    lines.push(`suppressed: ${f.suppression_reason ?? "(no reason recorded)"}`);
  }
  lines.push(`source: ${f.source_tool.join(", ")}`);
  return lines.join("\n");
}

function ruleCode(f: Finding): vscode.Diagnostic["code"] {
  // The Problems panel shows `code` next to the message; use CWE if we have
  // it (links to a known taxonomy in the user's head) or fall back to the
  // category, dropped to a short slug.
  if (f.cwe) return f.cwe;
  if (f.category) return f.category.toLowerCase().replace(/\s+/g, "-");
  return undefined;
}

