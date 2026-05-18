"""Tests for the Semgrep custom-rules pack support (Phase 4 §17 #6).

The container shell-out lives in sandbox.runner; this file just pins the
adapter behavior — env presence/absence drives `--config /custom-rules`
and the extra_mounts list.
"""
from __future__ import annotations

import importlib

import pytest

pytest.importorskip("pydantic")


def _fresh_adapter(monkeypatch, tmp_path, env_value=None):
    """Reload the module with the chosen env so module-level state is fresh."""
    if env_value is None:
        monkeypatch.delenv("SEMGREP_CUSTOM_RULES_DIR", raising=False)
    else:
        monkeypatch.setenv("SEMGREP_CUSTOM_RULES_DIR", env_value)
    from worker.scanners import semgrep as mod
    importlib.reload(mod)
    return mod.SemgrepAdapter()


def test_no_custom_dir_means_no_extra_config_or_mount(monkeypatch, tmp_path):
    a = _fresh_adapter(monkeypatch, tmp_path, env_value=None)
    cmd = a.command(tmp_path, tmp_path)
    assert a.extra_mounts == []
    assert "/custom-rules" not in cmd


def test_present_custom_dir_appends_config_and_mount(monkeypatch, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "noop.yaml").write_text("rules: []\n")
    a = _fresh_adapter(monkeypatch, tmp_path, env_value=str(rules))

    cmd = a.command(tmp_path, tmp_path)
    assert "/custom-rules" in cmd
    # Came AFTER the default packs, not in place of them.
    assert "p/owasp-top-ten" in cmd
    assert a.extra_mounts == [(rules, "/custom-rules", "ro")]


def test_missing_custom_dir_is_silently_skipped(monkeypatch, tmp_path):
    """Wrong path should NOT crash the scan — silently treated as if unset."""
    a = _fresh_adapter(monkeypatch, tmp_path, env_value=str(tmp_path / "does-not-exist"))
    assert a.extra_mounts == []
    cmd = a.command(tmp_path, tmp_path)
    assert "/custom-rules" not in cmd


def test_runner_rejects_reserved_container_paths(monkeypatch, tmp_path):
    """The runner refuses extra_mounts that collide with /repo, /out, /tmp."""
    from worker.sandbox.runner import SandboxError, run_scanner

    # Stub which() so we get to the validation branch, then patch subprocess
    # to confirm we never reach it.
    import worker.sandbox.runner as runner_mod

    monkeypatch.setattr(runner_mod.shutil, "which", lambda _: "/usr/bin/docker")

    called = {"ran": False}
    def _no_run(*a, **kw):
        called["ran"] = True
        raise AssertionError("should not have shelled out")
    monkeypatch.setattr(runner_mod.subprocess, "run", _no_run)

    with pytest.raises(SandboxError, match="reserved"):
        run_scanner(["echo"], tmp_path, tmp_path, extra_mounts=[(tmp_path, "/repo", "ro")])
    assert called["ran"] is False
