"""Unit tests for the finding-lifecycle service (Phase 4 §17 #4).

Covers the two pure pieces — `diff_against_baseline` and the suppression
expiry logic — without spinning up Postgres. The DB-bound paths
(`compute_audit_diff`, `active_suppressions`, route layer) are exercised
by the API integration tests in `tests/api/test_api_routes.py`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlalchemy")

from app.services.lifecycle import diff_against_baseline


@dataclass
class _Row:
    """Minimal FindingRow stand-in. Only `dedupe_key` matters for the diff."""
    dedupe_key: str
    title: str = ""


def test_diff_partitions_new_recurring_resolved():
    baseline = [_Row("a"), _Row("b"), _Row("c")]
    current = [_Row("a"), _Row("c"), _Row("d")]

    buckets = diff_against_baseline(current, baseline)

    assert [f.dedupe_key for f in buckets.new] == ["d"]
    assert {f.dedupe_key for f in buckets.recurring} == {"a", "c"}
    assert [f.dedupe_key for f in buckets.resolved] == ["b"]


def test_diff_empty_baseline_marks_everything_new():
    buckets = diff_against_baseline([_Row("a"), _Row("b")], [])
    assert {f.dedupe_key for f in buckets.new} == {"a", "b"}
    assert buckets.recurring == []
    assert buckets.resolved == []


def test_diff_empty_current_marks_everything_resolved():
    buckets = diff_against_baseline([], [_Row("a"), _Row("b")])
    assert buckets.new == []
    assert buckets.recurring == []
    assert {f.dedupe_key for f in buckets.resolved} == {"a", "b"}


def test_lifecycle_for_returns_bucket_membership():
    baseline = [_Row("old"), _Row("shared")]
    current = [_Row("shared"), _Row("fresh")]
    buckets = diff_against_baseline(current, baseline)

    assert buckets.lifecycle_for("fresh") == "new"
    assert buckets.lifecycle_for("shared") == "recurring"
    assert buckets.lifecycle_for("old") == "resolved"
    assert buckets.lifecycle_for("never-seen") is None


def test_lifecycle_for_short_circuits_on_first_match():
    """A dedupe_key only belongs to one bucket — `lifecycle_for` returns the
    first one it finds. Guards against future refactors accidentally returning
    multiple labels for the same key."""
    baseline = [_Row("a")]
    current = [_Row("a")]
    buckets = diff_against_baseline(current, baseline)

    # `a` should only appear in `recurring`, not in `new` or `resolved`.
    assert buckets.lifecycle_for("a") == "recurring"
    assert not any(f.dedupe_key == "a" for f in buckets.new)
    assert not any(f.dedupe_key == "a" for f in buckets.resolved)
