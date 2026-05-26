"""Tests for the virgil CLI.

The CLI is a thin shell over the HTTP API; tests mock the client module
so they exercise the command wiring + exit codes + the local pieces
(directory bundler, severity threshold logic) without needing a running
backend.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("click")
pytest.importorskip("rich")

# The CLI lives in apps/cli; add it to the path so the test runner can import
# it without a separate install step.
_CLI_ROOT = Path(__file__).resolve().parents[1] / "apps" / "cli"
sys.path.insert(0, str(_CLI_ROOT))

from click.testing import CliRunner  # noqa: E402

from cli.main import _bundle_dir, _breaches_threshold, _worst_severity, cli  # noqa: E402


# ---- bundler --------------------------------------------------------------


def test_bundler_skips_vendored_dirs(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.js").write_text("hostile\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    zip_path = _bundle_dir(tmp_path, out_dir)

    with zipfile.ZipFile(zip_path) as zf:
        names = sorted(zf.namelist())
    assert "src/app.py" in names
    assert not any(n.startswith("node_modules/") for n in names)
    assert not any(n.startswith(".git/") for n in names)


def test_bundler_drops_oversize_blobs(tmp_path: Path):
    (tmp_path / "ok.py").write_text("ok\n", encoding="utf-8")
    big = tmp_path / "huge.bin"
    big.write_bytes(b"x" * (51 * 1024 * 1024))  # 51MB — over the 50MB cap
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    zip_path = _bundle_dir(tmp_path, out_dir)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
    assert "ok.py" in names
    assert "huge.bin" not in names


# ---- severity-threshold helpers ------------------------------------------


def test_worst_severity_ignores_suppressed():
    findings = [
        {"severity": "Critical", "suppressed": True},
        {"severity": "High", "suppressed": False},
    ]
    assert _worst_severity(findings) == "High"


def test_worst_severity_none_when_empty():
    assert _worst_severity([]) is None
    assert _worst_severity([{"severity": "High", "suppressed": True}]) is None


def test_breaches_threshold_respects_never():
    findings = [{"severity": "Critical"}]
    assert _breaches_threshold(findings, "never") is False


def test_breaches_threshold_at_exact_match():
    """If --fail-on=high, a High finding breaches; a Medium does not."""
    assert _breaches_threshold([{"severity": "High"}], "high") is True
    assert _breaches_threshold([{"severity": "Medium"}], "high") is False
    assert _breaches_threshold([{"severity": "Critical"}], "high") is True


def test_breaches_threshold_with_no_findings():
    assert _breaches_threshold([], "critical") is False


# ---- scan command — end-to-end with mocked client -----------------------


def _patch_client(monkeypatch, *, audit_state="succeeded", findings=None, error=None):
    """Replace the network-touching functions in cli.main with stubs that
    return canned data. Patches at the import site (cli.main) so reloading
    isn't necessary."""
    if findings is None:
        findings = []
    audit = {
        "id": "11111111-1111-1111-1111-111111111111",
        "source_kind": "zip",
        "source_ref": "scan.zip",
        "state": audit_state,
        "phase": "completed" if audit_state == "succeeded" else "failed",
        "error": error,
        "profile": None,
    }
    monkeypatch.setattr("cli.main.submit_zip", lambda _path: audit)
    monkeypatch.setattr("cli.main.submit_url", lambda *a, **kw: audit)
    monkeypatch.setattr("cli.main.get_audit", lambda _aid: audit)
    monkeypatch.setattr("cli.main.list_findings", lambda _aid, **kw: findings)
    monkeypatch.setattr("cli.main.get_clusters", lambda _aid: {"items": []})
    # Stream ends immediately with a `done` event so the live spinner exits.
    monkeypatch.setattr("cli.main.stream_events", lambda _aid: iter([{"event": "done", "data": ""}]))


def test_scan_exits_zero_when_no_findings(monkeypatch, tmp_path: Path):
    _patch_client(monkeypatch, findings=[])
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output


def test_scan_exits_one_when_critical_present(monkeypatch, tmp_path: Path):
    _patch_client(monkeypatch, findings=[{"severity": "Critical", "title": "x",
                                          "category": "Injection", "affected_files": [],
                                          "affected_lines": []}])
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 1, result.output


def test_scan_fail_on_never_returns_zero_even_with_criticals(monkeypatch, tmp_path: Path):
    _patch_client(monkeypatch, findings=[{"severity": "Critical", "title": "x",
                                          "category": "Injection", "affected_files": [],
                                          "affected_lines": []}])
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "never"])
    assert result.exit_code == 0, result.output


def test_scan_exits_two_when_audit_failed(monkeypatch, tmp_path: Path):
    _patch_client(monkeypatch, audit_state="failed", error="clone exceeded 300s")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert "clone exceeded" in result.output


def test_scan_rejects_path_and_url_together(monkeypatch, tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--url", "https://github.com/x/y"])
    assert result.exit_code != 0
    assert "TARGET or --url" in result.output


def test_scan_unreachable_exits_three(monkeypatch, tmp_path: Path):
    from cli.client import ApiUnreachable

    def _boom(*a, **kw):
        raise ApiUnreachable("connection refused")

    monkeypatch.setattr("cli.main.submit_zip", _boom)
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 3, result.output
    assert "docker compose up" in result.output


# ---- findings + report commands ------------------------------------------


def test_findings_command_renders_table(monkeypatch):
    monkeypatch.setattr("cli.main.list_findings",
                        lambda _aid, **kw: [
                            {"severity": "High", "title": "SQLi",
                             "category": "Injection",
                             "affected_files": ["src/app.py"],
                             "affected_lines": [{"start": 42}],
                             "kev": False, "reachable": True},
                        ])
    runner = CliRunner()
    result = runner.invoke(cli, ["findings", "audit-id-x"])
    assert result.exit_code == 0
    assert "SQLi" in result.output


def test_report_command_writes_output_file(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("cli.main.get_report",
                        lambda _aid, view, format: b'{"hello": "world"}')
    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        cli, ["report", "audit-id-x", "--format", "json", "-o", str(out)],
    )
    assert result.exit_code == 0
    assert out.read_bytes() == b'{"hello": "world"}'
