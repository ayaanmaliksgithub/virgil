"""Tests for the demo-audit seed loader.

The seed runs at API container boot. A regression here means a fresh
`docker compose up` lands on an empty UI — the exact problem this
feature exists to prevent.

The schema-level checks are against the stand-in StubFindingRow shape so
the test runs without Postgres. The end-to-end loader path is exercised
indirectly by the helpers `_build_audit / _build_findings / …` which
construct real SQLAlchemy model instances and let us inspect them
without actually committing.
"""
from __future__ import annotations

import json
import os
from datetime import timezone
from pathlib import Path
from uuid import UUID

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

pytest.importorskip("pydantic")
pytest.importorskip("sqlalchemy")


def _fixture_path() -> Path:
    return Path(__file__).resolve().parents[1] / "apps" / "api" / "app" / "seed_data" / "nodegoat.json"


def _load_fixture() -> dict:
    return json.loads(_fixture_path().read_text(encoding="utf-8"))


# ---- structural invariants on the JSON itself ---------------------------


def test_fixture_audit_id_is_sentinel():
    data = _load_fixture()
    assert data["audit"]["id"].startswith("00000000-0000-0000-0000-")


def test_fixture_findings_belong_to_seed_audit():
    """No raw audit_id refs in the JSON — every finding inherits from the
    parent audit at insert time. The loader is the one place audit_id is
    set, and the test catches accidental hand-coded mismatches."""
    data = _load_fixture()
    for f in data["findings"]:
        # We don't store an audit_id key on the JSON finding by design;
        # _build_findings stamps it from data["audit"]["id"].
        assert "audit_id" not in f, "findings should not hand-code audit_id; loader sets it"


def test_fixture_has_priority_list_template():
    """The seed must surface the LLM-style priority queue immediately, even
    though no LLM ran. Loader resolves these into real cluster_keys."""
    data = _load_fixture()
    items = data["priority_list_template"]["items"]
    assert len(items) >= 5
    for entry in items:
        assert entry["triple"].count("|") == 2
        assert 20 <= len(entry["reason"]) <= 400


def test_fixture_has_at_least_one_kev_finding():
    """The triage UX is much weaker without a KEV-tagged finding to show."""
    data = _load_fixture()
    assert any(f.get("kev") for f in data["findings"])


def test_fixture_has_unreachable_dep_finding():
    """Reachability filtering is a headline feature; the demo loses force
    if no finding is `reachable=False`."""
    data = _load_fixture()
    deps = [f for f in data["findings"] if f["category"] == "Vulnerable Dependency"]
    assert any(f["reachable"] is False for f in deps)


def test_fixture_has_clusterable_repetition():
    """Clustering is a headline feature too. There must be at least one
    rule_id × category × cwe triple that appears 2+ times so the demo's
    cluster ledger has something to cluster."""
    data = _load_fixture()
    from collections import Counter
    triples = Counter()
    for f in data["findings"]:
        raw = f.get("raw_reference") or {}
        rule = raw.get("check_id") or raw.get("rule_id") or raw.get("pkg") or raw.get("id")
        triples[(f["category"], f.get("cwe"), rule)] += 1
    assert max(triples.values()) >= 3, "expected at least one cluster of 3+"


def test_fixture_compliance_fields_well_formed():
    """Every compliance entry must be a dict of framework → [control_ids]."""
    data = _load_fixture()
    for f in data["findings"]:
        c = f.get("compliance") or {}
        assert isinstance(c, dict)
        for framework, controls in c.items():
            assert framework in {"SOC2", "PCI-DSS", "HIPAA", "ISO27001"}
            assert isinstance(controls, list)
            assert all(isinstance(x, str) for x in controls)


def test_fixture_chat_session_grounded_in_real_finding_ids():
    """Pre-baked chat citations must reference findings that exist in the
    seed. A miss would render dead links."""
    data = _load_fixture()
    finding_ids = {f["id"] for f in data["findings"]}
    for m in data["chat_session"]["messages"]:
        for cite in m.get("citations") or []:
            assert cite in finding_ids, f"chat cite {cite!r} not in seeded findings"


# ---- loader behavior (without a real DB) -----------------------------


def test_resolve_triple_matches_cluster_key_hash():
    """Loader's _resolve_triple must produce the same key shape as
    services.clusters._cluster_key. Otherwise the priority_list points at
    keys that the cluster service can't find."""
    from app.seed import _cluster_key, _resolve_triple
    from app.services.clusters import _cluster_key as cluster_key_in_service

    # Build a stand-in FindingRow with the right fields for the service.
    class _Row:
        def __init__(self, **kw):
            self.__dict__.update(kw)
            for k in ("category", "cwe", "title", "raw_reference"):
                self.__dict__.setdefault(k, None)
    row = _Row(category="Injection", cwe="CWE-943",
               raw_reference={"check_id": "javascript.express.nosql-injection-mongodb"},
               title="t")
    service_key = cluster_key_in_service(row)
    seed_key = _resolve_triple(
        "Injection|CWE-943|rule:javascript.express.nosql-injection-mongodb"
    )
    assert service_key == seed_key, (
        "seed loader must produce keys that cluster_findings can find"
    )


def test_resolve_priority_list_preserves_order_and_resolves_keys():
    from app.seed import _resolve_priority_list
    out = _resolve_priority_list({
        "items": [
            {"triple": "Secret Exposure|CWE-798|rule:aws-access-token", "reason": "first"},
            {"triple": "Injection|CWE-943|rule:javascript.express.nosql-injection-mongodb", "reason": "second"},
        ]
    })
    assert [item["reason"] for item in out] == ["first", "second"]
    for item in out:
        assert len(item["cluster_key"]) == 16
        assert item["reason"]


def test_resolve_cluster_hints_skips_underscore_keys():
    """The JSON has a `_comment` key inside cluster_hints_template; the
    resolver must ignore it (not turn it into a cluster_key)."""
    from app.seed import _resolve_cluster_hints
    out = _resolve_cluster_hints({
        "_comment": "ignore me",
        "Injection|CWE-943|rule:foo": {"shared_dir": "x", "shared_modules": []},
    })
    assert len(out) == 1
    [(key, hint)] = out.items()
    assert hint == {"shared_dir": "x", "shared_modules": []}
    assert len(key) == 16


def test_build_audit_applies_resolved_templates():
    """The loader must merge the resolved priority_list + cluster_hints
    onto the audit's profile JSONB."""
    from app.seed import _build_audit
    data = _load_fixture()
    audit = _build_audit(data)
    profile = audit.profile
    assert isinstance(profile["priority_list"], list)
    assert len(profile["priority_list"]) >= 5
    assert isinstance(profile["cluster_hints"], dict)
    assert profile["cluster_hints"], "expected at least one hint"
    # The base narrative survives unchanged.
    assert "credential surface" in profile["narrative"]


def test_build_findings_populates_new_fields():
    """Regression guard: every finding must round-trip compliance, reachable,
    code_context, kev — the fields the rest of the product reads."""
    from app.seed import _build_findings
    data = _load_fixture()
    rows = _build_findings(data)
    assert len(rows) == len(data["findings"])
    # At least one finding exercises each new field.
    assert any(r.compliance for r in rows)
    assert any(r.reachable is False for r in rows)
    assert any(r.code_context for r in rows)
    assert any(r.kev for r in rows)


def test_build_findings_assigns_unique_dedupe_keys():
    """Two findings with different rule_ids must not collide on dedupe_key."""
    from app.seed import _build_findings
    data = _load_fixture()
    rows = _build_findings(data)
    keys = [r.dedupe_key for r in rows]
    assert len(set(keys)) == len(keys)


def test_seed_run_skipped_when_disabled(monkeypatch):
    """SEED_DEMO_AUDIT=false must early-return without touching the session."""
    from app import seed

    class _NoSession:
        def get(self, *a, **kw): raise AssertionError("must not query")
        def add(self, *a, **kw): raise AssertionError("must not add")
        def commit(self): raise AssertionError("must not commit")
        def flush(self): raise AssertionError("must not flush")
        def close(self): pass

    monkeypatch.setenv("SEED_DEMO_AUDIT", "false")
    assert seed.run(db=_NoSession()) is False


def test_seed_run_no_ops_when_audit_already_exists(monkeypatch):
    """Calling run() against a DB that already has the sentinel audit must
    skip — running this on a populated stack is safe."""
    from app import seed

    class _Existing:
        def __init__(self):
            self.calls = 0
        def get(self, model, id):
            self.calls += 1
            return object()  # truthy: row exists
        def add(self, *a, **kw): raise AssertionError("must not add")
        def commit(self): raise AssertionError("must not commit")
        def flush(self): raise AssertionError("must not flush")
        def close(self): pass

    monkeypatch.setenv("SEED_DEMO_AUDIT", "true")
    db = _Existing()
    assert seed.run(db=db) is False
    assert db.calls == 1, "loader should check exactly once for the sentinel UUID"
