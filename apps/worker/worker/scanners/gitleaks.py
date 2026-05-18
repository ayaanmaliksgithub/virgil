"""Gitleaks adapter — primary secret detection."""
from __future__ import annotations

import json
from pathlib import Path

from audit_core import RawFinding, RepoProfile

from .base import ScannerAdapter


class GitleaksAdapter:
    name = "gitleaks"
    version = "8.x"

    #: Set by the orchestrator before `command()` is called. Holds the *host*
    #: path to the cloned/extracted repo, separate from the container-side
    #: `/repo` path. We need the host path to decide history-vs-file-tree mode,
    #: because the `.git` directory check has to run on the worker's filesystem
    #: — the container hasn't started yet. Stays `None` in tests / direct use,
    #: in which case the `repo_path` argument is used as a fallback.
    host_repo_path: Path | None = None

    def applicable(self, profile: RepoProfile) -> bool:
        return profile.file_count > 0

    def command(self, repo_path: Path, out_dir: Path) -> list[str]:
        cmd = [
            "gitleaks", "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", str(out_dir / "gitleaks.json"),
            "--redact",
            "--exit-code", "0",
        ]
        # Walk commit history when the host repo carries a `.git` dir (URL
        # intake). ZIP uploads land as a plain tree, so fall back to file-tree
        # mode — gitleaks errors out in history mode without a git dir.
        detect_path = self.host_repo_path if self.host_repo_path is not None else repo_path
        if not (detect_path / ".git").is_dir():
            cmd.append("--no-git")
        return cmd

    def parse(self, out_dir: Path) -> list[RawFinding]:
        out_file = out_dir / "gitleaks.json"
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            return []
        # gitleaks emits a top-level list
        if not isinstance(data, list):
            return []

        results: list[RawFinding] = []
        for f in data:
            rule_id = str(f.get("RuleID") or "gitleaks-unknown")
            commit = str(f.get("Commit") or "").strip()
            # History-mode hits carry a non-zero Commit SHA; file-tree mode leaves it blank.
            historical = bool(commit) and not commit.startswith("0000")
            description = str(f.get("Description") or rule_id)
            title = f"Potential secret: {description}"
            if historical:
                title = f"Potential secret (historical commit {commit[:7]}): {description}"

            raw_extras: dict[str, object] = {"rule_id": rule_id, "entropy": f.get("Entropy")}
            if historical:
                raw_extras.update({
                    "commit": commit,
                    "author": f.get("Author"),
                    "email": f.get("Email"),
                    "date": f.get("Date"),
                    "commit_message": (str(f.get("Message") or "")[:240]) or None,
                    "historical": True,
                })

            results.append(RawFinding(
                source_tool="gitleaks",
                rule_id=f"secret/{rule_id}",
                title=title[:256],
                raw_severity="HIGH",
                message=description[:2000],
                file=str(f.get("File", "")),
                start_line=int(f.get("StartLine") or 1) or 1,
                end_line=int(f.get("EndLine") or 0) or None,
                snippet=f.get("Match") or f.get("Secret"),
                cwe="CWE-798",
                cve=None,
                owasp="A07:2021 - Identification and Authentication Failures",
                raw=raw_extras,
            ))
        return results
