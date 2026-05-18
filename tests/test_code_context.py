"""Tests for code-context extraction.

Code context is the difference between chat that talks about a finding
in the abstract and chat that says "the input on line 42 is already
parameterized two lines up". These tests pin the slicing window,
redaction pipeline, path-escape rejection, and graceful skip for
missing files / binary content.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.normalize.code_context import (
    CONTEXT_LINES_AFTER,
    CONTEXT_LINES_BEFORE,
    MAX_CONTEXT_BYTES,
    extract_slice,
    enrich_with_code_context,
)


def _file(tmp_path: Path, name: str, lines: list[str]) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _finding(file: str, line: int) -> Finding:
    return Finding(
        dedupe_key=f"dk-{file}:{line}",
        title=f"finding at {file}:{line}",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Injection",
        affected_files=[file],
        affected_lines=[AffectedLine(file=file, start=line)],
        evidence="x",
        explanation="y",
        source_tool=["semgrep"],
        status=Status.OPEN,
    )


def test_window_centers_on_target_line(tmp_path: Path):
    _file(tmp_path, "app.py", [f"line {i}" for i in range(1, 101)])
    out = extract_slice(tmp_path, "app.py", 50)
    assert out is not None
    # the target line is present and number-prefixed
    assert "50  line 50" in out
    # window extends backward by CONTEXT_LINES_BEFORE
    assert f"{50 - CONTEXT_LINES_BEFORE}  line {50 - CONTEXT_LINES_BEFORE}" in out
    # …and forward by CONTEXT_LINES_AFTER
    assert f"{50 + CONTEXT_LINES_AFTER}  line {50 + CONTEXT_LINES_AFTER}" in out


def test_window_clamps_at_file_start(tmp_path: Path):
    _file(tmp_path, "small.py", ["alpha", "beta", "gamma"])
    out = extract_slice(tmp_path, "small.py", 1)
    assert out is not None
    assert "1  alpha" in out
    assert "3  gamma" in out  # we get the whole file
    # no negative line numbers leak in
    assert "0  " not in out


def test_redaction_applied_to_slice(tmp_path: Path):
    _file(
        tmp_path,
        "config.py",
        ["import os", 'AKIAIOSFODNN7EXAMPLE = "secret"', "x = 1"],
    )
    out = extract_slice(tmp_path, "config.py", 2)
    assert out is not None
    # AWS key pattern gets redacted before storage.
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_path_escape_returns_none(tmp_path: Path):
    _file(tmp_path, "inside.py", ["hello"])
    outside = tmp_path.parent / "escape.py"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        # Even if a finding reports `../escape.py`, the resolver refuses.
        out = extract_slice(tmp_path, "../escape.py", 1)
        assert out is None
    finally:
        outside.unlink(missing_ok=True)


def test_missing_file_returns_none(tmp_path: Path):
    assert extract_slice(tmp_path, "nope.py", 1) is None


def test_enricher_attaches_context_and_skips_when_unreadable(tmp_path: Path):
    _file(tmp_path, "ok.py", ["one", "two", "three"])
    f_ok = _finding("ok.py", 2)
    f_missing = _finding("does-not-exist.py", 1)

    out = enrich_with_code_context([f_ok, f_missing], tmp_path)

    assert out[0].code_context is not None
    assert "2  two" in out[0].code_context
    assert out[1].code_context is None  # gracefully skipped


def test_byte_cap_enforced(tmp_path: Path):
    # Lines long enough to overflow MAX_CONTEXT_BYTES once windowed.
    bigline = "x" * 200
    _file(tmp_path, "big.py", [bigline for _ in range(60)])
    out = extract_slice(tmp_path, "big.py", 30)
    assert out is not None
    # MAX_CONTEXT_BYTES is a soft cap; the marker is appended in bytes (the
    # `…` is 3 UTF-8 bytes), so the final blob is bounded by the cap plus
    # the marker's byte length.
    marker_bytes = len("\n… (truncated)".encode("utf-8"))
    assert len(out.encode("utf-8")) <= MAX_CONTEXT_BYTES + marker_bytes + 1
    assert "truncated" in out


def test_enricher_no_op_when_finding_has_no_affected_lines(tmp_path: Path):
    f = Finding(
        dedupe_key="dk",
        title="t",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category="x",
        affected_files=["any.py"],
        affected_lines=[],
        evidence="x",
        explanation="y",
        source_tool=["x"],
        status=Status.OPEN,
    )
    [out] = enrich_with_code_context([f], tmp_path)
    assert out.code_context is None
