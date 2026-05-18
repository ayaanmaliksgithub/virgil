from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from audit_core import RepoProfile
from worker.scanners.codeql import CodeQLAdapter


def test_codeql_is_opt_in(monkeypatch):
    profile = RepoProfile(languages={"Python": 1}, file_count=1)
    adapter = CodeQLAdapter()

    monkeypatch.delenv("ENABLE_CODEQL", raising=False)
    assert adapter.applicable(profile) is False

    monkeypatch.setenv("ENABLE_CODEQL", "true")
    assert adapter.applicable(profile) is True


def test_codeql_command_uses_detected_and_allowed_languages(monkeypatch):
    profile = RepoProfile(languages={"Python": 2, "JavaScript": 1, "Rust": 1}, file_count=4)
    adapter = CodeQLAdapter()

    monkeypatch.setenv("ENABLE_CODEQL", "true")
    monkeypatch.setenv("CODEQL_LANGUAGES", "python")

    assert adapter.applicable(profile) is True
    argv = adapter.command(Path("/repo"), Path("/out"))
    script = argv[-1]

    assert argv[:2] == ["sh", "-lc"]
    assert "--language=python" in script
    assert "python-security-and-quality.qls" in script
    assert "javascript-security-and-quality.qls" not in script
    assert "--source-root=/repo" in script
    assert "--output=/out/codeql-python.sarif" in script


def test_codeql_parse_sarif(tmp_path):
    out_dir = tmp_path
    (out_dir / "codeql-python.sarif").write_text(json.dumps(_sarif()), encoding="utf-8")

    findings = CodeQLAdapter().parse(out_dir)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_tool == "codeql"
    assert finding.rule_id == "py/path-injection"
    assert finding.title == "Uncontrolled data used in path expression"
    assert finding.raw_severity == "HIGH"
    assert finding.file == "app/views.py"
    assert finding.start_line == 42
    assert finding.end_line == 43
    assert finding.cwe == "CWE-22"
    assert finding.owasp == "OWASP-A01"
    assert finding.raw["security_severity"] == "8.1"


def _sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/path-injection",
                                "shortDescription": {
                                    "text": "Uncontrolled data used in path expression"
                                },
                                "fullDescription": {
                                    "text": "User-controlled data is used in a filesystem path."
                                },
                                "properties": {
                                    "precision": "high",
                                    "security-severity": "8.1",
                                    "tags": [
                                        "security",
                                        "external/cwe/cwe-022",
                                        "external/owasp/owasp-a01",
                                    ],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/path-injection",
                        "level": "warning",
                        "message": {"text": "This path depends on user input."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/views.py"},
                                    "region": {"startLine": 42, "endLine": 43},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
