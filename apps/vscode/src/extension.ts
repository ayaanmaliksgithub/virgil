/**
 * Virgil VS Code extension — entrypoint.
 *
 * The extension is a thin UI host that drives the bundled `virgil` CLI. The
 * CLI talks to the Virgil API; the extension talks only to the CLI over
 * stdio. This is the same architecture the Claude Code and Codex extensions
 * use: keep one mature binary as the source of truth and let the editor
 * surface its results.
 *
 * Workflows:
 *   - `Virgil: Scan workspace` — runs `virgil scan . --no-wait`, stashes the
 *     returned audit id in workspace state, kicks off a refresh loop.
 *   - `Virgil: Track an existing audit ID` — pin an audit you already
 *     produced from the terminal or web UI; the extension surfaces its
 *     findings inline.
 *   - Inline diagnostics auto-refresh every 5 minutes (or on manual
 *     `Virgil: Refresh diagnostics`), so findings appear as the audit
 *     completes server-side.
 *
 * The first time any command runs the CLI, the extension downloads the
 * matching binary for the user's OS/arch from the Virgil GitHub Release.
 * No Python or pipx required.
 */
import * as vscode from "vscode";
import { runVirgil, scan, listFindings, getAudit, CliError } from "./cli";
import { BinaryError } from "./binary";
import { buildDiagnostics } from "./diagnostics";
import type { Severity, Finding } from "./types";

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
    vscode.commands.registerCommand("virgil.scan", () => scanWorkspace(context)),
    vscode.commands.registerCommand("virgil.setAudit", () => setAudit(context)),
    vscode.commands.registerCommand("virgil.clearAudit", () => clearAudit(context)),
    vscode.commands.registerCommand("virgil.refresh", () => refresh(context)),
    vscode.commands.registerCommand("virgil.openInBrowser", () => openInBrowser(context)),
  );

  refreshTimer = setInterval(() => {
    void refresh(context, { silent: true });
  }, REFRESH_INTERVAL_MS);
  context.subscriptions.push({ dispose: () => clearInterval(refreshTimer!) });

  void refresh(context, { silent: true });

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

async function scanWorkspace(context: vscode.ExtensionContext): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showWarningMessage(
      "Virgil: open a folder before running a scan.",
    );
    return;
  }
  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Virgil: submitting scan",
        cancellable: false,
      },
      () => scan(context, folder.uri.fsPath),
    );
    const auditId = result.audit.id;
    await context.workspaceState.update(STATE_AUDIT_ID, auditId);
    void vscode.window.showInformationMessage(
      `Virgil: tracking audit ${auditId.slice(0, 8)} — diagnostics will refresh as it completes.`,
    );
    void refresh(context, { silent: true });
  } catch (e) {
    void vscode.window.showErrorMessage(`Virgil: ${describeError(e)}`);
  }
}

async function setAudit(context: vscode.ExtensionContext): Promise<void> {
  const current = context.workspaceState.get<string>(STATE_AUDIT_ID, "");
  const id = await vscode.window.showInputBox({
    title: "Virgil audit ID",
    prompt: "Paste an audit UUID from `virgil scan` output or the web UI.",
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
  try {
    const audit = await getAudit(context, trimmed);
    await context.workspaceState.update(STATE_AUDIT_ID, audit.id);
    void vscode.window.showInformationMessage(
      `Virgil: tracking audit ${audit.id.slice(0, 8)} (${audit.state}) for this workspace`,
    );
    await refresh(context);
  } catch (e) {
    void vscode.window.showErrorMessage(`Virgil: ${describeError(e)}`);
  }
}

async function clearAudit(context: vscode.ExtensionContext): Promise<void> {
  await context.workspaceState.update(STATE_AUDIT_ID, undefined);
  diagnosticCollection.clear();
  statusBar.text = "$(shield) virgil: cleared";
  statusBar.tooltip = "Run 'Virgil: Scan workspace' to start a new audit";
}

async function refresh(
  context: vscode.ExtensionContext,
  opts: { silent?: boolean } = {},
): Promise<void> {
  const auditId = context.workspaceState.get<string>(STATE_AUDIT_ID, "");
  if (!auditId) {
    statusBar.text = "$(shield) virgil: no audit";
    statusBar.tooltip =
      "Run 'Virgil: Scan workspace' (or 'Virgil: Track an existing audit ID')";
    diagnosticCollection.clear();
    return;
  }

  const cfg = vscode.workspace.getConfiguration("virgil");
  const includeSuppressed = cfg.get<boolean>("includeSuppressed", false);
  const minSeverity = cfg.get<Severity>("minSeverity", "Low");

  try {
    const findings = await listFindings(context, auditId, { includeSuppressed });
    const folders = vscode.workspace.workspaceFolders ?? [];
    const grouped = buildDiagnostics(findings, { minSeverity, folders });

    diagnosticCollection.clear();
    for (const { uri, diags } of grouped.values()) {
      diagnosticCollection.set(uri, diags);
    }

    const counts = severityCounts(findings);
    statusBar.text = renderStatus(counts, auditId);
    statusBar.tooltip = renderTooltip(counts, auditId);
  } catch (e) {
    statusBar.text = isUnreachable(e)
      ? "$(alert) virgil: API unreachable"
      : "$(alert) virgil: error";
    statusBar.tooltip = describeError(e);
    if (!opts.silent) {
      void vscode.window.showWarningMessage(`Virgil: ${describeError(e)}`);
    }
  }
}

async function openInBrowser(context: vscode.ExtensionContext): Promise<void> {
  const auditId = context.workspaceState.get<string>(STATE_AUDIT_ID, "");
  if (!auditId) {
    void vscode.commands.executeCommand("virgil.scan");
    return;
  }
  try {
    // Delegate URL building to the CLI so the web_url config lives in one
    // place (the CLI's config file / env vars).
    const result = await runVirgil<never>(context, [
      "open",
      auditId,
      "--print",
    ]);
    const url = result.stdout.trim();
    if (!url) {
      void vscode.window.showErrorMessage("Virgil: could not determine the web URL");
      return;
    }
    await vscode.env.openExternal(vscode.Uri.parse(url));
  } catch (e) {
    void vscode.window.showErrorMessage(`Virgil: ${describeError(e)}`);
  }
}

// ---------- helpers ----------

interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  kev: number;
}

function severityCounts(findings: Finding[]): Counts {
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
  const parts: string[] = [];
  if (c.critical) parts.push(`${c.critical}C`);
  if (c.high) parts.push(`${c.high}H`);
  if (c.medium) parts.push(`${c.medium}M`);
  if (c.low) parts.push(`${c.low}L`);
  if (c.kev) parts.push(`${c.kev}!KEV`);
  return `$(shield) virgil: ${parts.join(" ")} · ${idPrefix}`;
}

function renderTooltip(c: Counts, auditId: string): string {
  return [
    `Virgil audit ${auditId}`,
    ``,
    `Critical: ${c.critical}`,
    `High:     ${c.high}`,
    `Medium:   ${c.medium}`,
    `Low:      ${c.low}`,
    `Info:     ${c.info}`,
    `KEV:      ${c.kev}`,
    ``,
    `Click to open the audit in your browser.`,
  ].join("\n");
}

function isUnreachable(e: unknown): boolean {
  // The CLI exits 3 when it can't reach the API. See `apps/cli/cli/main.py`.
  return e instanceof CliError && e.exitCode === 3;
}

function describeError(e: unknown): string {
  if (e instanceof BinaryError) {
    if (e.kind === "unsupported") return e.message;
    if (e.kind === "download") return `couldn't download the CLI binary: ${e.message}`;
    return e.message;
  }
  if (e instanceof CliError) {
    if (e.exitCode === 3) {
      return (
        "API unreachable. Set the API URL with " +
        "`virgil config set api_url=…` or start a local instance " +
        "(`docker compose up`)."
      );
    }
    if (e.exitCode === 2 && /not found/i.test(e.stderr)) {
      return "audit not found at this API";
    }
    return e.message;
  }
  return e instanceof Error ? e.message : String(e);
}
