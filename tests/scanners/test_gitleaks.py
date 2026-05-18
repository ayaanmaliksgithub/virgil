"""Gitleaks adapter tests — covers the Phase-4 history-scanning mode.

These tests assert two behaviors that together let us walk commit history:

1. When the repo has a real `.git` directory (URL-intake path), the adapter
   builds a command WITHOUT `--no-git`, so gitleaks walks the log.
2. When the repo has no `.git` (ZIP-intake path), the adapter falls back to
   `--no-git` because history mode would error.

Plus: history-mode output carries commit metadata that the previous parser
dropped. We now surface it in `raw` and tag the title so triagers can tell
a current-tree leak from a years-old historical one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from worker.scanners.gitleaks import GitleaksAdapter


def test_command_walks_history_when_host_repo_has_git_dir(tmp_path: Path):
    """Production path: tasks.py passes container path `/repo` as repo_path
    AND sets `host_repo_path` on the adapter to the on-disk clone location.
    The `.git` check must happen on the host path, not the container path."""
    host_repo = tmp_path / "repo"
    (host_repo / ".git").mkdir(parents=True)
    out = tmp_path / "out"
    out.mkdir()

    adapter = GitleaksAdapter()
    adapter.host_repo_path = host_repo
    cmd = adapter.command(Path("/repo"), out)  # container-side path on purpose

    assert "--no-git" not in cmd, "history scan must NOT pass --no-git"
    assert cmd[:2] == ["gitleaks", "detect"]
    assert "--redact" in cmd
    # The argv-level --source still references the container path, not the host
    assert "--source" in cmd
    assert "/repo" in cmd


def test_command_falls_back_to_file_mode_for_zip_intake(tmp_path: Path):
    """ZIP intake leaves no .git dir on the host — adapter must add --no-git."""
    host_repo = tmp_path / "repo"
    host_repo.mkdir()  # no .git subdir
    out = tmp_path / "out"
    out.mkdir()

    adapter = GitleaksAdapter()
    adapter.host_repo_path = host_repo
    cmd = adapter.command(Path("/repo"), out)

    assert "--no-git" in cmd


def test_command_falls_back_to_repo_path_when_host_attr_not_set(tmp_path: Path):
    """Direct callers (tests, scripts) that don't set host_repo_path get
    the legacy behavior — detection runs against repo_path."""
    host_repo = tmp_path / "repo"
    (host_repo / ".git").mkdir(parents=True)

    # No host_repo_path set — passing host path as repo_path keeps the
    # detection working for non-tasks.py callers.
    cmd = GitleaksAdapter().command(host_repo, tmp_path / "out")
    assert "--no-git" not in cmd


def test_parse_marks_historical_commit_metadata(tmp_path: Path):
    out = tmp_path
    payload = [{
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "src/old/config.py",
        "StartLine": 12,
        "EndLine": 12,
        "Match": "AKIA****************",
        "Secret": "AKIA****************",
        "Entropy": 4.2,
        "Commit": "deadbeefcafebabe1234567890abcdef12345678",
        "Author": "Former Employee",
        "Email": "gone@example.com",
        "Date": "2022-04-01T10:00:00Z",
        "Message": "wip: temporary creds for staging",
    }]
    (out / "gitleaks.json").write_text(json.dumps(payload), encoding="utf-8")

    findings = GitleaksAdapter().parse(out)

    assert len(findings) == 1
    rf = findings[0]
    assert "historical commit deadbee" in rf.title
    assert rf.raw["historical"] is True
    assert rf.raw["commit"] == "deadbeefcafebabe1234567890abcdef12345678"
    assert rf.raw["author"] == "Former Employee"
    assert rf.raw["commit_message"].startswith("wip:")


def test_parse_leaves_current_tree_finding_unmarked(tmp_path: Path):
    out = tmp_path
    payload = [{
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "config/keys.yml",
        "StartLine": 3,
        "EndLine": 3,
        "Match": "redacted",
        "Commit": "",  # file-tree mode emits empty commit
    }]
    (out / "gitleaks.json").write_text(json.dumps(payload), encoding="utf-8")

    findings = GitleaksAdapter().parse(out)

    assert len(findings) == 1
    assert "historical" not in findings[0].title.lower()
    assert "historical" not in findings[0].raw
