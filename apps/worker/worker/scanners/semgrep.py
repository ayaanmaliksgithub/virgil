"""Semgrep adapter.

Runs the configured Semgrep packs and parses the JSON output.
Default packs are audit-oriented (OWASP Top 10 + security-audit + secrets) and
overridable via SEMGREP_RULESETS.

Phase 4 §17 #6 — operators can layer their own rule pack on top by setting
`SEMGREP_CUSTOM_RULES_DIR` to a host-side directory of `*.yaml` Semgrep rule
files. The worker bind-mounts it read-only at `/custom-rules` and Semgrep
walks it recursively. The sandbox stays `--network=none`, so remote rule URLs
will NOT work at runtime — pre-fetch them into the bound directory.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from audit_core import RawFinding, RepoProfile

from .base import ScannerAdapter

DEFAULT_RULESETS = "p/owasp-top-ten,p/security-audit,p/secrets"
CUSTOM_RULES_MOUNT = "/custom-rules"


class SemgrepAdapter:
    name = "semgrep"
    version = "1.x"

    # Populated by `tasks.py` if SEMGREP_CUSTOM_RULES_DIR is set — see
    # `extra_mounts` for how this flows into the sandbox.
    custom_rules_dir: Path | None = None

    def __init__(self) -> None:
        raw = os.environ.get("SEMGREP_CUSTOM_RULES_DIR", "").strip()
        if raw:
            p = Path(raw)
            if p.is_dir():
                self.custom_rules_dir = p
            # If the path is wrong we silently skip — `tasks.py` logs the
            # mount list per scan so the operator sees what was offered.

    @property
    def extra_mounts(self) -> list[tuple[Path, str, str]]:
        if self.custom_rules_dir is None:
            return []
        return [(self.custom_rules_dir, CUSTOM_RULES_MOUNT, "ro")]

    def applicable(self, profile: RepoProfile) -> bool:
        return profile.file_count > 0

    def command(self, repo_path: Path, out_dir: Path) -> list[str]:
        rulesets = os.environ.get("SEMGREP_RULESETS", DEFAULT_RULESETS)
        config_args: list[str] = []
        for r in (r.strip() for r in rulesets.split(",") if r.strip()):
            config_args += ["--config", r]
        if self.custom_rules_dir is not None:
            config_args += ["--config", CUSTOM_RULES_MOUNT]
        return [
            "semgrep", "scan",
            *config_args,
            "--json",
            "--output", str(out_dir / "semgrep.json"),
            "--metrics", "off",
            "--quiet",
            "--timeout", "120",
            "--disable-version-check",
            str(repo_path),
        ]

    def parse(self, out_dir: Path) -> list[RawFinding]:
        out_file = out_dir / "semgrep.json"
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            return []

        results: list[RawFinding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            severity = extra.get("severity") or metadata.get("severity")
            cwe = metadata.get("cwe")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else None
            owasp = metadata.get("owasp")
            if isinstance(owasp, list):
                owasp = owasp[0] if owasp else None

            results.append(RawFinding(
                source_tool=self.name,
                rule_id=str(r.get("check_id", "semgrep-unknown")),
                title=str(metadata.get("shortDescription") or extra.get("message") or r.get("check_id") or "Semgrep finding")[:256],
                raw_severity=severity,
                message=str(extra.get("message") or "")[:8000],
                file=str(r.get("path", "")),
                start_line=int((r.get("start") or {}).get("line") or 1),
                end_line=int((r.get("end") or {}).get("line") or 0) or None,
                snippet=(extra.get("lines") or None),
                cwe=_normalize_cwe(cwe),
                cve=None,
                owasp=_normalize_owasp(owasp),
                raw={"check_id": r.get("check_id"), "metadata": metadata},
            ))
        return results


def _normalize_cwe(value) -> str | None:
    if not value:
        return None
    s = str(value)
    if s.startswith("CWE-"):
        return s.split(":", 1)[0]
    # Sometimes "CWE-79: XSS"
    if "CWE-" in s:
        idx = s.index("CWE-")
        rest = s[idx + 4:]
        num = ""
        for ch in rest:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            return f"CWE-{num}"
    return None


def _normalize_owasp(value) -> str | None:
    if not value:
        return None
    s = str(value)
    # Semgrep metadata often looks like "A01:2021 - Broken Access Control"
    return s
