# Changelog

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
