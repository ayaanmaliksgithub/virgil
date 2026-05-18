"""Tests for the PR-mode diff parser + finding filter (Phase 4 §17 #5).

The shell-out paths (`compute_changed_lines`) need git + docker so they're
exercised only by the compose smoke test. Here we cover the two pure
functions that decide which findings survive PR-mode.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.pr_mode import filter_findings_by_diff, parse_unified_diff


SAMPLE_DIFF = """\
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -10,2 +10,3 @@ def handler():
 ctx = build()
-old_call()
+new_call()
+log(ctx)
diff --git a/src/util.py b/src/util.py
--- a/src/util.py
+++ b/src/util.py
@@ -42 +42 @@
-x = 1
+x = 2
diff --git a/docs/dead.md b/docs/dead.md
--- a/docs/dead.md
+++ /dev/null
@@ -1,3 +0,0 @@
-line one
-line two
-line three
"""


def _f(file: str, start: int, end: int | None = None) -> Finding:
    return Finding(
        dedupe_key=f"{file}:{start}",
        title=f"finding @ {file}:{start}",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Injection",
        affected_files=[file],
        affected_lines=[AffectedLine(file=file, start=start, end=end)],
        evidence="x",
        explanation="y",
        source_tool=["semgrep"],
        status=Status.OPEN,
    )


def test_parse_unified_diff_extracts_added_and_changed_lines():
    changed = parse_unified_diff(SAMPLE_DIFF)
    assert changed["src/app.py"] == {11, 12}
    assert changed["src/util.py"] == {42}
    # Pure deletions drop out — no head-side lines.
    assert "docs/dead.md" not in changed


def test_filter_keeps_findings_overlapping_diff():
    changed = parse_unified_diff(SAMPLE_DIFF)
    in_diff = _f("src/app.py", 11)
    in_diff_range = _f("src/app.py", 10, end=12)  # range covers a changed line
    outside = _f("src/app.py", 30)
    kept = filter_findings_by_diff([in_diff, in_diff_range, outside], changed)
    assert {f.dedupe_key for f in kept} == {in_diff.dedupe_key, in_diff_range.dedupe_key}


def test_filter_drops_findings_in_untouched_files():
    changed = parse_unified_diff(SAMPLE_DIFF)
    unrelated = _f("src/other.py", 1)
    assert filter_findings_by_diff([unrelated], changed) == []


def test_filter_falls_back_to_file_only_for_findings_without_lines():
    """Repo-wide findings (e.g. a dep CVE) have no line context. PR-mode
    keeps them if any of their affected_files appears in the diff."""
    changed = parse_unified_diff(SAMPLE_DIFF)
    dep = Finding(
        dedupe_key="dep:lodash",
        title="lodash CVE",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Vulnerable Dependency",
        affected_files=["src/app.py"],
        affected_lines=[],
        evidence="x",
        explanation="y",
        source_tool=["trivy"],
        status=Status.OPEN,
    )
    assert filter_findings_by_diff([dep], changed) == [dep]


def test_filter_matches_basename_suffix_when_paths_differ():
    """Some adapters emit paths with extra prefixes. The matcher allows a
    suffix overlap so `/repo/src/app.py` still resolves to the diff key
    `src/app.py`."""
    changed = parse_unified_diff(SAMPLE_DIFF)
    prefixed = _f("/repo/src/app.py", 11)
    assert filter_findings_by_diff([prefixed], changed) == [prefixed]


def test_parse_handles_multiple_hunks_in_one_file():
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x
+y
@@ -10,0 +11,2 @@
+new1
+new2
"""
    changed = parse_unified_diff(diff)
    assert changed["a.py"] == {1, 11, 12}
