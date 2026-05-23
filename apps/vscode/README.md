# Virgil for VS Code

> Self-hosted security audit, inside your editor. Run scans, surface findings
> as inline diagnostics, and triage from the command palette — powered by the
> bundled [Virgil](https://github.com/ayaanmaliksgithub/virgil) CLI.

## Install

The extension is not yet published to the Marketplace. For now:

```bash
cd apps/vscode
npm install
npm run compile
```

Then, in VS Code:
- `code --install-extension .` from `apps/vscode/` (with the `vsce` CLI), or
- Open the folder in a separate VS Code window and run the **Extensions: Install from VSIX…** command pointing at the packaged output.

## How it works

The extension is a thin UI host. All work — submitting scans, polling for
findings, talking to the API — is delegated to the bundled `virgil` CLI,
the same one users run from the terminal (`pipx install virgilhq`).

On first activation the extension downloads a single-file binary built for
your OS + architecture from the project's GitHub Release. No Python or pipx
required for end users. The binary is cached under VS Code's extension
storage and reused on subsequent launches.

This is the same architecture the Claude Code and Codex VS Code extensions
use: keep one mature binary as the source of truth, let the editor surface
its output. It means the extension inherits everything the CLI can already
do — scan, cluster, chat, report — without each surface having to be
reimplemented in TypeScript.

## What you get today

- **`Virgil: Scan workspace`** — submits a scan against the open folder,
  pins the resulting audit to the workspace, and starts polling for
  findings.
- **`Virgil: Track an existing audit ID`** — paste an audit UUID you
  produced elsewhere (CLI, web UI, CI) and the extension will surface its
  findings inline.
- **Inline diagnostics.** Every finding becomes a VS Code diagnostic on the
  matching file + line range. Severity maps to VS Code's 4-level enum:
  - Critical / High → Error
  - Medium → Warning
  - Low → Information
  - Informational → Hint
- **Status-bar rollup.** A compact `virgil: 2C 7H 12M · c9b1d8a3` shows
  critical/high/medium counts plus the audit-ID prefix. Click to open the
  audit in your browser.
- **Auto-refresh** every 5 minutes while VS Code is open, plus a manual
  **`Virgil: Refresh diagnostics`** command.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| `virgil.cliPath` | _(empty)_ | Optional path to a locally-built `virgil` binary. Set this while developing the CLI alongside the extension. |
| `virgil.minSeverity` | `Low` | Lowest severity to surface as a diagnostic. |
| `virgil.includeSuppressed` | `false` | Show findings suppressed on the server. |

The API URL (and other backend addressing) lives in the CLI's own config —
`virgil config set api_url=https://virgil.example.com/api`. The extension
never needs to know.

## What this extension explicitly does NOT do (yet)

- **No write paths.** Suppression, baseline management, and severity
  overrides live in the web UI. The extension is read-only against the API.
- **No exploit content.** Same product principle as the rest of Virgil —
  no payloads, no exact patches, no step-by-step reproduction.

## On the roadmap

- Sidebar webview with ranked clusters, jump-to-file, and grounded chat.
- "Explain this finding" code action that opens chat seeded with the
  finding ID.
- Auto-discover the latest audit for the workspace via the git remote.

## License

Apache 2.0. See the [project LICENSE](https://github.com/ayaanmaliksgithub/virgil/blob/main/LICENSE).
