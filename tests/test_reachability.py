"""Tests for the reachability analyzer (Phase 4 §17 #8).

The analyzer is the highest-leverage noise-reduction feature in the
product — every regression here directly hurts trust in the findings
ledger. Tests cover: AST + regex collectors, scoped-name handling
(`@scope/pkg`), dist-name vs import-name normalization for Python,
fail-open behavior on syntax errors, severity demotion, abstain when
no source files of the relevant language were parsed, and the
non-dep-finding pass-through.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.normalize.reachability import (
    build_import_index,
    enrich_with_reachability,
)


def _f(*, category: str = "Vulnerable Dependency", pkg: str | None = "requests",
       severity: Severity = Severity.HIGH, file: str = "requirements.txt") -> Finding:
    return Finding(
        dedupe_key=f"{category}:{pkg or 'none'}:{file}",
        title=f"{pkg or 'finding'} CVE",
        severity=severity,
        confidence=Confidence.HIGH,
        category=category,
        affected_files=[file],
        affected_lines=[AffectedLine(file=file, start=1)],
        evidence="x",
        explanation="y",
        source_tool=["trivy"],
        raw_reference={"pkg": pkg} if pkg else {},
        status=Status.OPEN,
    )


# ---- import-index walker ---------------------------------------------------


def test_python_collector_picks_up_import_and_from_forms(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import requests\nfrom flask import Flask\nimport lib.sub\nfrom . import siblng\n",
        encoding="utf-8",
    )
    idx = build_import_index(tmp_path)
    assert idx.python == frozenset({"requests", "flask", "lib"})
    assert idx.python_seen_files == 1


def test_python_collector_skips_relative_imports(tmp_path: Path):
    (tmp_path / "app.py").write_text("from . import sibling\nfrom ..pkg import x\n", encoding="utf-8")
    idx = build_import_index(tmp_path)
    assert idx.python == frozenset()


def test_python_collector_fails_open_on_syntax_error(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def x(\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("import boto3\n", encoding="utf-8")
    idx = build_import_index(tmp_path)
    assert "boto3" in idx.python
    assert idx.python_seen_files == 2  # both attempted, one yielded zero


def test_js_collector_handles_import_require_and_dynamic(tmp_path: Path):
    (tmp_path / "app.ts").write_text(
        "import { x } from 'react';\n"
        "import lodash from \"lodash\";\n"
        "const fs = require('fs');\n"
        "const mod = await import('@scope/pkg/sub');\n"
        "import './relative';\n"
        "import '/abs';\n",
        encoding="utf-8",
    )
    idx = build_import_index(tmp_path)
    # scoped packages keep the @scope/name pair; sub-paths are stripped
    assert "react" in idx.javascript
    assert "lodash" in idx.javascript
    assert "fs" in idx.javascript
    assert "@scope/pkg" in idx.javascript
    # relative + absolute file paths are not packages
    assert "./relative" not in idx.javascript
    assert "/abs" not in idx.javascript


def test_walker_skips_vendored_dirs(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "evil.js").write_text("require('attacker')", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.js").write_text("require('legit')", encoding="utf-8")
    idx = build_import_index(tmp_path)
    assert "legit" in idx.javascript
    assert "attacker" not in idx.javascript


# ---- enricher --------------------------------------------------------------


def test_unreachable_dep_demotes_severity_and_marks_false(tmp_path: Path):
    (tmp_path / "app.py").write_text("import boto3\n", encoding="utf-8")
    out, stats = enrich_with_reachability(
        [_f(pkg="requests", severity=Severity.HIGH, file="requirements.txt")],
        tmp_path,
    )
    assert out[0].reachable is False
    assert out[0].severity == Severity.MEDIUM
    assert stats["unreachable"] == 1
    assert stats["reachable"] == 0


def test_reachable_dep_keeps_severity_and_marks_true(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    out, _ = enrich_with_reachability(
        [_f(pkg="requests", severity=Severity.HIGH, file="requirements.txt")],
        tmp_path,
    )
    assert out[0].reachable is True
    assert out[0].severity == Severity.HIGH


def test_dist_name_with_dashes_matches_underscore_import(tmp_path: Path):
    """`google-cloud-storage` (dist) imports as `google.cloud.storage`. The
    enricher normalizes both sides so the join works."""
    (tmp_path / "app.py").write_text("import google\n", encoding="utf-8")
    out, _ = enrich_with_reachability(
        [_f(pkg="google-cloud-storage", file="requirements.txt")],
        tmp_path,
    )
    assert out[0].reachable is True


def test_abstain_when_no_source_files_of_that_language(tmp_path: Path):
    """No Python files parsed → we cannot say a Python dep is unreachable.
    Better to leave the finding at full severity than wrongly demote."""
    (tmp_path / "app.ts").write_text("import 'react';\n", encoding="utf-8")
    out, stats = enrich_with_reachability(
        [_f(pkg="requests", severity=Severity.HIGH, file="requirements.txt")],
        tmp_path,
    )
    assert out[0].reachable is None
    assert out[0].severity == Severity.HIGH
    assert stats["abstained"] == 1


def test_non_dep_findings_pass_through_untouched(tmp_path: Path):
    (tmp_path / "app.py").write_text("import json\n", encoding="utf-8")
    sqli = _f(category="Injection", pkg=None, file="src/app.py")
    out, stats = enrich_with_reachability([sqli], tmp_path)
    assert out[0].reachable is None  # untouched (default)
    assert out[0].severity == Severity.HIGH
    assert stats["checked"] == 0


def test_js_dep_unreachable_when_package_not_imported(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text("import react from 'react'\n", encoding="utf-8")
    out, _ = enrich_with_reachability(
        [_f(pkg="lodash", severity=Severity.CRITICAL, file="package-lock.json")],
        tmp_path,
    )
    assert out[0].reachable is False
    assert out[0].severity == Severity.HIGH  # Critical → High demote


# ---- Go / Ruby / Java collectors ------------------------------------------


def test_go_collector_picks_up_single_and_grouped(tmp_path: Path):
    (tmp_path / "main.go").write_text(
        'package main\n'
        'import "fmt"\n'
        'import alias "github.com/foo/bar"\n'
        'import (\n'
        '    "encoding/json"\n'
        '    other "github.com/baz/qux"\n'
        ')\n',
        encoding="utf-8",
    )
    idx = build_import_index(tmp_path)
    assert "fmt" in idx.go
    assert "github.com/foo/bar" in idx.go
    assert "encoding/json" in idx.go
    assert "github.com/baz/qux" in idx.go


def test_go_pkg_match_handles_subpath_imports(tmp_path: Path):
    (tmp_path / "main.go").write_text(
        'package main\nimport "github.com/foo/bar/internal/util"\n',
        encoding="utf-8",
    )
    out, _ = enrich_with_reachability(
        [_f(category="Vulnerable Dependency", pkg="github.com/foo/bar",
            file="go.sum")],
        tmp_path,
    )
    assert out[0].reachable is True


def test_go_unreachable_when_module_not_imported(tmp_path: Path):
    (tmp_path / "main.go").write_text(
        'package main\nimport "fmt"\n', encoding="utf-8",
    )
    out, _ = enrich_with_reachability(
        [_f(category="Vulnerable Dependency", pkg="github.com/foo/bar",
            severity=Severity.CRITICAL, file="go.sum")],
        tmp_path,
    )
    assert out[0].reachable is False
    assert out[0].severity == Severity.HIGH  # demoted


def test_ruby_collector_extracts_requires_and_gems(tmp_path: Path):
    (tmp_path / "app.rb").write_text(
        "require 'json'\n"
        'require "nokogiri"\n'
        "gem 'rails'\n"
        "require './local_module'\n",
        encoding="utf-8",
    )
    idx = build_import_index(tmp_path)
    assert "json" in idx.ruby
    assert "nokogiri" in idx.ruby
    assert "rails" in idx.ruby
    # relative paths excluded
    assert not any(i.startswith(".") for i in idx.ruby)


def test_ruby_dep_unreachable_when_not_required(tmp_path: Path):
    (tmp_path / "app.rb").write_text("require 'json'\n", encoding="utf-8")
    out, _ = enrich_with_reachability(
        [_f(category="Vulnerable Dependency", pkg="nokogiri", file="Gemfile.lock")],
        tmp_path,
    )
    assert out[0].reachable is False


def test_java_collector_extracts_package_not_class(tmp_path: Path):
    (tmp_path / "X.java").write_text(
        "package com.example;\n"
        "import com.fasterxml.jackson.databind.ObjectMapper;\n"
        "import java.util.List;\n"
        "import static org.junit.Assert.assertEquals;\n",
        encoding="utf-8",
    )
    idx = build_import_index(tmp_path)
    # Drops the final identifier (class name) — we keep the package.
    assert "com.fasterxml.jackson.databind" in idx.java
    assert "java.util" in idx.java
    assert "org.junit" in idx.java


def test_java_maven_coord_matches_by_group_id_prefix(tmp_path: Path):
    """Trivy reports `com.fasterxml.jackson.core:jackson-databind`; we match
    if any imported package starts with `com.fasterxml.jackson.core`."""
    (tmp_path / "X.java").write_text(
        "import com.fasterxml.jackson.core.JsonParser;\n", encoding="utf-8",
    )
    out, _ = enrich_with_reachability(
        [_f(category="Vulnerable Dependency",
            pkg="com.fasterxml.jackson.core:jackson-databind",
            file="pom.xml")],
        tmp_path,
    )
    assert out[0].reachable is True


def test_java_unreachable_dep_demoted(tmp_path: Path):
    (tmp_path / "X.java").write_text(
        "import java.util.List;\n", encoding="utf-8",
    )
    out, _ = enrich_with_reachability(
        [_f(category="Vulnerable Dependency",
            pkg="org.apache.logging.log4j:log4j-core",
            severity=Severity.CRITICAL, file="pom.xml")],
        tmp_path,
    )
    assert out[0].reachable is False
    assert out[0].severity == Severity.HIGH


def test_kotlin_files_share_java_index(tmp_path: Path):
    (tmp_path / "X.kt").write_text(
        "import com.example.foo.Bar\n", encoding="utf-8",
    )
    idx = build_import_index(tmp_path)
    assert "com.example.foo" in idx.java
    assert idx.java_seen_files >= 1


def test_informational_does_not_underflow_on_demote(tmp_path: Path):
    (tmp_path / "app.py").write_text("import nothing\n", encoding="utf-8")
    out, _ = enrich_with_reachability(
        [_f(pkg="requests", severity=Severity.INFORMATIONAL, file="requirements.txt")],
        tmp_path,
    )
    assert out[0].reachable is False
    assert out[0].severity == Severity.INFORMATIONAL  # stays at floor
