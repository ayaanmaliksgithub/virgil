/**
 * Virgil VS Code extension — entrypoint.
 *
 * The extension is intentionally read-only against the Virgil API: it polls
 * the configured audit's findings and surfaces them as VS Code diagnostics
 * on the matching files + lines. No write paths (suppression, baseline
 * management, etc.) — those live in the web UI.
 *
 * Lifecycle:
 *   1. `activate()` registers commands + the status-bar item, then triggers
 *      an initial refresh against the audit ID stored in workspace state.
 *   2. `virgil.setAudit` lets the user paste an audit UUID; the extension
 *      validates by GETing the audit, then stores the ID per-workspace.
 *   3. `virgil.refresh` re-fetches findings and rebuilds the diagnostic
 *      collection. Bound to a 5-minute auto-refresh while VS Code is open.
 *
 * Audit-ID auto-discovery from `git remote` is on the roadmap but explicitly
 * out of scope for v0.1 — the user pastes the audit ID once per workspace.
 */
import * as vscode from "vscode";
import { ApiError, ApiUnreachable, getAudit, listFindings } from "./api";
import { buildDiagnostics } from "./diagnostics";
import type { Severity } from "./types";

const STATE_AUDIT_ID = "virgil.auditId";
const REFRESH_INTERVAL_MS = 5 * 60 * 1000;

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let refreshTimer: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection("virgil");
  context.subscriptions.push(diagnosticCollection);

  statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100,
  );
  statusBar.command = "virgil.openInBrowser";
  statusBar.text = "$(shield) virgil: idle";
  statusBar.tooltip = "Click to open the current Virgil audit in your browser";
  statusBar.show();
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand("virgil.setAudit", () => setAudit(context)),
    vscode.commands.registerCommand("virgil.clearAudit", () => clearAudit(context)),
    vscode.commands.registerCommand("virgil.refresh", () => refresh(context)),
    vscode.commands.registerCommand("virgil.openInBrowser", () => openInBrowser(context)),
  );

  // Auto-refresh while VS Code is open. Light cadence; the diagnostics only
  // change when a new audit completes.
  refreshTimer = setInterval(() => {
    void refresh(context, { silent: true });
  }, REFRESH_INTERVAL_MS);
  context.subscriptions.push({ dispose: () => clearInterval(refreshTimer!) });

  // Initial paint on activation. Silent so no popup on a workspace that
  // hasn't been configured yet.
  void refresh(context, { silent: true });

  // React to settings changes (API URL, minSeverity, …) without requiring a
  // reload.
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("virgil")) {
        void refresh(context, { silent: true });
      }
    }),
  );
}

export function deactivate(): void {
  if (refreshTimer) clearInterval(refreshTimer);
  diagnosticCollection?.dispose();
  statusBar?.dispose();
}

// ---------- commands ----------

async function setAudit(context: vscode.ExtensionContext): Promise<void> {
  const current = context.workspaceState.get<string>(STATE_AUDIT_ID, "");
  const id = await vscode.window.showInputBox({
    title: "Virgil audit ID",
    prompt: "Paste an audit UUID. Get it from the web UI or `virgil scan .` output.",
    value: current,
    validateInput: (v) =>
      v && !/^[0-9a-fA-F-]{8,}$/.test(v.trim())
        ? "doesn't look like a UUID"
        : null,
  });
  if (id === undefined) return; // cancelled
  const trimmed = id.trim();
  if (!trimmed) {
    await context.workspaceState.update(STATE_AUDIT_ID, undefined);
    diagnosticCollection.clear();
    statusBar.text = "$(shield) virgil: cleared";
    return;
  }

  // Validate by fetching — gives the user immediate feedback that the API is
  // reachable AND the audit exists.
  const base = config().get<string>("api", "http://localhost:8000");
  try {
    const audit = await getAudit(base, trimmed);
    await context.workspaceState.update(STATE_AUDIT_ID, audit.id);
    vscode.window.showInformationMessage(
      `Virgil: tracking audit ${audit.id.slice(0, 8)} (${audit.state}) for this workspace`,
    );
    await refresh(context);
  } catch (e) {
    vscode.window.showErrorMessage(`Virgil: ${describeError(e)}`);
  }
}

async function clearAudit(context: vscode.ExtensionContext): Promise<void> {
  await context.workspaceState.update(STATE_AUDIT_ID, undefined);
  diagnosticCollection.clear();
  statusBar.text = "$(shield) virgil: cleared";
  statusBar.tooltip = "Run 'Virgil: Set Audit ID' to start surfacing diagnostics";
}

async function refresh(
  context: vscode.ExtensionContext,
  opts: { silent?: boolean } = {},
): Promise<void> {
  const auditId = context.workspaceState.get<string>(STATE_AUDIT_ID, "");
  if (!auditId) {
    statusBar.text = "$(shield) virgil: no audit";
    statusBar.tooltip = "Run 'Virgil: Set Audit ID' to start surfacing diagnostics";
    diagnosticCollection.clear();
    return;
  }

  const cfg = config();
  const base = cfg.get<string>("api", "http://localhost:8000");
  const includeSuppressed = cfg.get<boolean>("includeSuppressed", false);
  const minSeverity = cfg.get<Severity>("minSeverity", "Low");

  try {
    const findings = await listFindings(base, auditId, { includeSuppressed });
    const folders = vscode.workspace.workspaceFolders ?? [];
    const grouped = buildDiagnostics(findings, { minSeverity, folders });

    diagnosticCollection.clear();
    for (const { uri, diags } of grouped.values()) {
      diagnosticCollection.set(uri, diags);
    }

    const counts = severityCounts(findings);
    statusBar.text = renderStatus(counts, auditId);
    statusBar.tooltip = renderTooltip(counts, auditId, base);
  } catch (e) {
    statusBar.text = "$(alert) virgil: unreachable";
    statusBar.tooltip = describeError(e);
    if (!opts.silent) {
      vscode.window.showWarningMessage(`Virgil: ${describeError(e)}`);
    }
  }
}

async function openInBrowser(context: vscode.ExtensionContext): Promise<void> {
  const auditId = context.workspaceState.get<string>(STATE_AUDIT_ID, "");
  if (!auditId) {
    void vscode.commands.executeCommand("virgil.setAudit");
    return;
  }
  const cfg = config();
  const webUrl = cfg.get<string>("webUrl", "http://localhost:3000").replace(/\/+$/, "");
  await vscode.env.openExternal(vscode.Uri.parse(`${webUrl}/audits/${auditId}`));
}

// ---------- helpers ----------

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("virgil");
}

interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  kev: number;
}

function severityCounts(findings: { severity: Severity; kev?: boolean; suppressed?: boolean }[]): Counts {
  const c: Counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0, kev: 0 };
  for (const f of findings) {
    if (f.suppressed) continue;
    c.total += 1;
    switch (f.severity) {
      case "Critical": c.critical += 1; break;
      case "High":     c.high     += 1; break;
      case "Medium":   c.medium   += 1; break;
      case "Low":      c.low      += 1; break;
      case "Informational": c.info += 1; break;
    }
    if (f.kev) c.kev += 1;
  }
  return c;
}

function renderStatus(c: Counts, auditId: string): string {
  const idPrefix = auditId.slice(0, 8);
  if (c.total === 0) {
    return `$(shield) virgil: clean · ${idPrefix}`;
  }
  // Compact summary; full breakdown lives in the tooltip.
  const parts: string[] = [];
  if (c.critical) parts.push(`${c.critical}C`);
  if (c.high) parts.push(`${c.high}H`);
  if (c.medium) parts.push(`${c.medium}M`);
  if (c.low) parts.push(`${c.low}L`);
  if (c.kev) parts.push(`${c.kev}!KEV`);
  return `$(shield) virgil: ${parts.join(" ")} · ${idPrefix}`;
}

function renderTooltip(c: Counts, auditId: string, base: string): string {
  const lines = [
    `Virgil audit ${auditId}`,
    ``,
    `Critical: ${c.critical}`,
    `High:     ${c.high}`,
    `Medium:   ${c.medium}`,
    `Low:      ${c.low}`,
    `Info:     ${c.info}`,
    `KEV:      ${c.kev}`,
    ``,
    `API: ${base}`,
    `Click to open the audit in your browser.`,
  ];
  return lines.join("\n");
}

function describeError(e: unknown): string {
  if (e instanceof ApiUnreachable) {
    return "API unreachable — is `docker compose up` running?";
  }
  if (e instanceof ApiError) {
    if (e.status === 404) return "audit not found at this API";
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}
