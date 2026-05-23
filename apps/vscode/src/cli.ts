/**
 * Spawn the bundled `virgil` CLI and collect its output.
 *
 * All command paths in the extension go through `runVirgil` — the CLI is the
 * single source of truth for talking to the Virgil API. The extension never
 * hits the API directly, which means:
 *
 *   - We don't need a DNS / hostname here; the CLI's own config owns that.
 *   - Auth, retries, SSE framing, the JSON shape — all of it stays in one
 *     place (`apps/cli/`) and is shared with the terminal experience.
 *
 * The `--json` global flag is passed *before* the subcommand to match how
 * Click resolves the option group (see `apps/cli/cli/main.py`).
 */
import { spawn } from "node:child_process";
import * as vscode from "vscode";
import { resolveBinary } from "./binary";
import type { Finding } from "./types";

let _channel: vscode.OutputChannel | undefined;

function channel(): vscode.OutputChannel {
  if (!_channel) _channel = vscode.window.createOutputChannel("Virgil");
  return _channel;
}

export interface CliResult<T = unknown> {
  exitCode: number;
  stdout: string;
  stderr: string;
  /** Parsed stdout if it was valid JSON. */
  json?: T;
}

export class CliError extends Error {
  constructor(
    public exitCode: number,
    public stderr: string,
    message: string,
  ) {
    super(message);
    this.name = "CliError";
  }
}

interface RunOpts {
  cwd?: string;
  /**
   * Exit codes treated as "ran successfully" rather than as errors. The CLI
   * uses `1` to mean "ran fine, found findings that breached --fail-on" —
   * the extension doesn't gate on that, so by default we accept 0 and 1.
   */
  acceptableExitCodes?: number[];
}

export async function runVirgil<T = unknown>(
  context: vscode.ExtensionContext,
  args: string[],
  opts: RunOpts = {},
): Promise<CliResult<T>> {
  const bin = await resolveBinary(context);
  const full = ["--json", ...args];
  channel().appendLine(
    `$ ${bin} ${full.join(" ")}${opts.cwd ? ` (cwd=${opts.cwd})` : ""}`,
  );

  return new Promise<CliResult<T>>((resolve, reject) => {
    const child = spawn(bin, full, { cwd: opts.cwd, env: process.env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (b: Buffer) => {
      stdout += b.toString();
    });
    child.stderr.on("data", (b: Buffer) => {
      const s = b.toString();
      stderr += s;
      channel().append(s);
    });
    child.on("error", (e) =>
      reject(new CliError(-1, stderr, `failed to spawn virgil: ${e.message}`)),
    );
    child.on("close", (code) => {
      const exitCode = code ?? 0;
      let json: T | undefined;
      if (stdout.trim()) {
        try {
          json = JSON.parse(stdout) as T;
        } catch {
          // Non-JSON stdout is fine for some flows (e.g. `report --format md`);
          // callers that need it will check `json` themselves.
        }
      }
      const accepted = opts.acceptableExitCodes ?? [0, 1];
      if (!accepted.includes(exitCode)) {
        reject(
          new CliError(
            exitCode,
            stderr,
            `virgil exited ${exitCode}: ${stderr.trim().slice(0, 240) || "(no stderr)"}`,
          ),
        );
        return;
      }
      resolve({ exitCode, stdout, stderr, json });
    });
  });
}

// ---- typed convenience wrappers used by the rest of the extension ---------

interface ScanJson {
  audit: { id: string; state: string; phase: string };
  submitted?: boolean;
  waited?: boolean;
}

/** Submit a scan for `cwd` and return as soon as the CLI has an audit ID. */
export async function scan(
  context: vscode.ExtensionContext,
  cwd: string,
): Promise<ScanJson> {
  const result = await runVirgil<ScanJson>(context, ["scan", cwd, "--no-wait"], {
    cwd,
  });
  if (!result.json?.audit?.id) {
    throw new CliError(
      result.exitCode,
      result.stderr,
      "virgil scan returned no audit id",
    );
  }
  return result.json;
}

interface FindingsJson {
  items: Finding[];
  count: number;
}

export async function listFindings(
  context: vscode.ExtensionContext,
  auditId: string,
  opts: { includeSuppressed?: boolean } = {},
): Promise<Finding[]> {
  const args = ["findings", auditId];
  if (opts.includeSuppressed) args.push("--include-suppressed");
  const result = await runVirgil<FindingsJson>(context, args);
  return result.json?.items ?? [];
}

interface AuditJson {
  id: string;
  state: "pending" | "running" | "succeeded" | "failed";
  phase: string;
}

export async function getAudit(
  context: vscode.ExtensionContext,
  auditId: string,
): Promise<AuditJson> {
  const result = await runVirgil<AuditJson>(context, ["status", auditId]);
  if (!result.json?.id) {
    throw new CliError(
      result.exitCode,
      result.stderr,
      "virgil status returned no audit",
    );
  }
  return result.json;
}
