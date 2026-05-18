"""Tests for license-risk classification + the Trivy license-finding parser
(Phase 4, item #3).

The classifier is policy-driven (LICENSE_POLICY env var). Tests cover all three
policies plus the env-resolution path; the Trivy parser test asserts permissive
licenses are suppressed and copyleft entries surface with the right severity.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from worker.normalize.category import categorize
from worker.normalize.licenses import classify_license
from worker.scanners.trivy import TrivyAdapter


# -- classifier ---------------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("AGPL-3.0", "HIGH"),
    ("agpl-3.0-or-later", "HIGH"),
    ("GPL-2.0", "HIGH"),
    ("SSPL-1.0", "HIGH"),
    ("LGPL-2.1", "MEDIUM"),
    ("MPL-2.0", "MEDIUM"),
    ("EPL-2.0", "MEDIUM"),
    ("MIT", None),
    ("Apache-2.0", None),
    ("BSD-3-Clause", None),
    ("ISC", None),
    ("0BSD", None),
    ("", "MEDIUM"),            # missing → manual-review medium under default
    ("WeirdProprietary", "MEDIUM"),
])
def test_classify_default_permissive_policy(monkeypatch, name, expected):
    monkeypatch.delenv("LICENSE_POLICY", raising=False)
    assert classify_license(name) == expected


def test_classify_strict_escalates_unknown_to_high(monkeypatch):
    monkeypatch.setenv("LICENSE_POLICY", "strict")
    assert classify_license("MysteryLicense") == "HIGH"
    assert classify_license("") == "HIGH"
    # Permissive still suppressed even under strict
    assert classify_license("MIT") is None
    # Strong copyleft unchanged
    assert classify_license("AGPL-3.0") == "HIGH"


def test_classify_copyleft_only_mutes_everything_except_strong_copyleft(monkeypatch):
    monkeypatch.setenv("LICENSE_POLICY", "copyleft-only")
    assert classify_license("AGPL-3.0") == "HIGH"
    assert classify_license("SSPL-1.0") == "HIGH"
    # Weak copyleft is suppressed entirely under this policy
    assert classify_license("LGPL-2.1") is None
    # Permissive suppressed
    assert classify_license("MIT") is None
    # Unknown → informational (not silenced — still worth a note)
    assert classify_license("UnknownThing") == "INFORMATIONAL"


def test_classify_invalid_policy_falls_back_to_permissive(monkeypatch):
    monkeypatch.setenv("LICENSE_POLICY", "yolo")
    assert classify_license("GPL-3.0") == "HIGH"
    assert classify_license("MIT") is None


# -- trivy adapter integration ------------------------------------------------

def test_trivy_license_findings_parsed_and_categorized(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("LICENSE_POLICY", raising=False)
    out = tmp_path
    payload = {
        "Results": [{
            "Target": "package.json",
            "Class": "lang-pkgs",
            "Licenses": [
                {"PkgName": "left-pad", "Name": "AGPL-3.0",   "Category": "restricted",  "Severity": "HIGH",   "FilePath": "package.json"},
                {"PkgName": "lodash",   "Name": "MIT",        "Category": "notice",      "Severity": "LOW"},
                {"PkgName": "openssl",  "Name": "LGPL-2.1",   "Category": "reciprocal",  "Severity": "MEDIUM"},
                {"PkgName": "weird",    "Name": "Proprietary","Category": "unknown",     "Severity": "UNKNOWN"},
            ],
        }],
    }
    (out / "trivy.json").write_text(json.dumps(payload), encoding="utf-8")

    findings = TrivyAdapter().parse(out)

    # MIT must be suppressed; the other three surface
    by_pkg = {f.raw["pkg"]: f for f in findings if f.rule_id.startswith("license/")}
    assert set(by_pkg.keys()) == {"left-pad", "openssl", "weird"}
    assert by_pkg["left-pad"].raw_severity == "HIGH"
    assert by_pkg["openssl"].raw_severity == "MEDIUM"
    assert by_pkg["weird"].raw_severity == "MEDIUM"  # unknown under default policy

    # category mapping should recognize the rule_id prefix
    rf = by_pkg["left-pad"]
    assert categorize(rf) == "License Risk"
    assert rf.title.startswith("License risk:")
    assert rf.raw["license"] == "AGPL-3.0"


def test_trivy_license_scan_enabled_in_command(tmp_path: Path):
    cmd = TrivyAdapter().command(tmp_path / "repo", tmp_path / "out")
    scanners_idx = cmd.index("--scanners")
    assert "license" in cmd[scanners_idx + 1].split(",")
