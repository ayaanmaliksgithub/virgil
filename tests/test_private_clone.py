from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from worker.clone import clone_repo


def _stub_runtime(monkeypatch, tmp_path: Path, captured: list[list[str]]):
    """Wire monkeypatches so clone_repo runs without docker and records argv."""
    monkeypatch.setattr("worker.clone.shutil.which", lambda runtime: f"/usr/bin/{runtime}")

    def fake_run(cmd, **kwargs):
        captured.append(cmd)
        if "clone" in cmd:
            repo = tmp_path / "repo"
            repo.mkdir(exist_ok=True)
            (repo / "README.md").write_text("ok\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")

    monkeypatch.setattr("worker.clone.subprocess.run", fake_run)


def test_clone_with_github_token_uses_askpass_without_leaking_token(monkeypatch, tmp_path):
    token = "ghp_private_token_value"
    commands: list[list[str]] = []

    monkeypatch.setattr("worker.clone.shutil.which", lambda runtime: f"/usr/bin/{runtime}")

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        if "clone" in cmd:
            repo = tmp_path / "repo"
            repo.mkdir()
            (repo / "README.md").write_text("ok\n", encoding="utf-8")
            assert (tmp_path / ".git-askpass").exists()
            assert (tmp_path / ".github-token").read_text(encoding="utf-8") == token
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")

    monkeypatch.setattr("worker.clone.subprocess.run", fake_run)

    sha = clone_repo("https://github.com/example/private-repo", tmp_path, github_token=token)

    assert sha == "abc123"
    assert not (tmp_path / ".git-askpass").exists()
    assert not (tmp_path / ".github-token").exists()
    flattened = " ".join(part for cmd in commands for part in cmd)
    assert token not in flattened
    assert "GIT_ASKPASS=/work/.git-askpass" in flattened
    assert "GIT_TERMINAL_PROMPT=0" in flattened


def test_clone_defaults_to_full_history_no_depth_flag(monkeypatch, tmp_path):
    """Phase-4 default: drop --depth=1 so Gitleaks can walk git log."""
    captured: list[list[str]] = []
    _stub_runtime(monkeypatch, tmp_path, captured)
    monkeypatch.delenv("CLONE_DEPTH", raising=False)

    clone_repo("https://github.com/example/public-repo", tmp_path)

    clone_cmd = next(c for c in captured if "clone" in c)
    assert not any(p.startswith("--depth") for p in clone_cmd), (
        f"default clone must include full history, got: {clone_cmd}"
    )
    assert "--no-tags" in clone_cmd and "--single-branch" in clone_cmd


@pytest.mark.parametrize("depth_env,expected_flag", [
    ("1", "--depth=1"),
    ("50", "--depth=50"),
])
def test_clone_honors_clone_depth_env(monkeypatch, tmp_path, depth_env, expected_flag):
    captured: list[list[str]] = []
    _stub_runtime(monkeypatch, tmp_path, captured)
    monkeypatch.setenv("CLONE_DEPTH", depth_env)

    clone_repo("https://github.com/example/public-repo", tmp_path)

    clone_cmd = next(c for c in captured if "clone" in c)
    assert expected_flag in clone_cmd


@pytest.mark.parametrize("bad_value", ["0", "-3", "deep", ""])
def test_clone_ignores_invalid_clone_depth(monkeypatch, tmp_path, bad_value):
    """Zero, negative, or non-integer depth falls back to full history."""
    captured: list[list[str]] = []
    _stub_runtime(monkeypatch, tmp_path, captured)
    monkeypatch.setenv("CLONE_DEPTH", bad_value)

    clone_repo("https://github.com/example/public-repo", tmp_path)

    clone_cmd = next(c for c in captured if "clone" in c)
    assert not any(p.startswith("--depth") for p in clone_cmd)
