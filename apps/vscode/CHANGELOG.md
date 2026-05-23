# Changelog

## 0.2.0 — CLI-backed extension

The extension now bundles the Virgil CLI as a single-file binary downloaded
on first activation. End users no longer need Python or pipx; the extension
spawns the binary directly and talks to it over stdio. Same architectural
pattern as the Claude Code and Codex VS Code extensions.

- **New:** `Virgil: Scan workspace` command — submits a scan against the
  open folder and pins the resulting audit automatically.
- **New:** `virgil.cliPath` setting — point at a locally-built binary
  (e.g. `apps/cli/dist/virgil`) for dev loops.
- **Changed:** all API access routes through the CLI. The extension no
  longer needs to know the backend URL — that lives in the CLI's own
  config (`virgil config set api_url=…`).
- **Removed:** `virgil.api` and `virgil.webUrl` settings (superseded by
  CLI config).
- **Removed:** direct HTTP client (`src/api.ts`).
- **Renamed:** `Virgil: Set Audit ID` → `Virgil: Track an existing audit ID`
  to reflect the new scan-from-IDE flow.

## 0.1.0 — initial release

- Inline diagnostics on every finding the configured audit returns,
  attached to the matching workspace file + line range with severity
  mapped to VS Code's 4-level diagnostic enum.
- Status-bar rollup: `virgil: <severityCounts> · <auditId-prefix>`,
  click to open the audit in your browser.
- Per-workspace audit ID via **Virgil: Set Audit ID** command,
  validated against the API on entry.
- Auto-refresh every 5 minutes; manual **Virgil: Refresh diagnostics**
  command.
- Settings: `virgil.api`, `virgil.webUrl`, `virgil.minSeverity`,
  `virgil.includeSuppressed`.
