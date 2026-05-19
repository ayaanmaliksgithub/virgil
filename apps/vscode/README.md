# Virgil for VS Code

> Inline security-audit annotations from a running [Virgil](https://github.com/ayaanmaliksgithub/virgil)
> instance. Findings appear as diagnostics on the lines the scanners
> flagged; the status bar shows the severity rollup at a glance.

## Install

The extension is not yet published to the Marketplace. For now:

```bash
cd apps/vscode
npm install
npm run compile
```

Then, in VS Code:
- `code --install-extension .` from `apps/vscode/` (with the `vsce`
  CLI), or
- Open the folder in a separate VS Code window and run the **Extensions:
  Install from VSIX…** command pointing at the packaged output.

(Marketplace publish is on the roadmap.)

## What it does

- **Inline diagnostics.** Every finding the API returns for the
  configured audit ID lands as a VS Code diagnostic on the matching
  file + line range. Severity → diagnostic level:
  - Critical / High → Error
  - Medium → Warning
  - Low → Information
  - Informational → Hint
- **Status bar rollup.** A compact `virgil: 2C 7H 12M · c9b1d8a3`
  shows critical/high/medium counts and the audit-ID prefix.
  Click to open the audit in your browser.
- **Per-workspace audit ID.** Pinned via workspace state. Run
  **Virgil: Set Audit ID** to enter the UUID you got from
  `virgil scan .` or the web UI.
- **Auto-refresh every 5 minutes** while VS Code is open, plus a
  manual **Virgil: Refresh diagnostics** command.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| `virgil.api` | `http://localhost:8000` | Base URL of the Virgil API |
| `virgil.webUrl` | `http://localhost:3000` | Base URL of the web UI (used by *Open in browser*) |
| `virgil.minSeverity` | `Low` | Lowest severity to surface as a diagnostic |
| `virgil.includeSuppressed` | `false` | Show findings suppressed on the server |

## What this extension explicitly does NOT do

- **No write paths.** Suppression, baseline management, and severity
  overrides live in the web UI. The extension is read-only against
  the API.
- **No new scans.** Use the CLI (`virgil scan .`) or the web form to
  submit an audit. The extension just surfaces findings from a
  completed audit.
- **No exploit content.** Same product principle as the rest of
  Virgil — no payloads, no exact patches, no step-by-step
  reproduction in any feature.

## Roadmap

- Auto-discover the latest audit ID for the workspace via the git
  remote + a `/v1/audits?source_ref=…` query.
- "Explain this finding" sidebar that calls the chat endpoint.
- Inline code action: "Suppress this finding…" with the reason prompt.

## License

Apache 2.0. See the [project LICENSE](https://github.com/ayaanmaliksgithub/virgil/blob/main/LICENSE).
