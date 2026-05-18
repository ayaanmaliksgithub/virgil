"""Tests for the LLM priority list (Phase 4 triage layer).

The LLM call is mocked via the provider; the test is the gating logic:
fallback when no provider, hallucinated key rejection, duplicate
rejection, safety sanitization, and the deterministic fallback shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

pytest.importorskip("pydantic")


@dataclass
class FakeCluster:
    key: str
    title: str = "A finding"
    severity: str = "High"
    category: str = "Injection"
    cwe: str | None = "CWE-89"
    instances: int = 3
    files: list = field(default_factory=lambda: ["a.py", "b.py"])
    cves: list = field(default_factory=list)
    kev: bool = False
    any_unreachable: bool = False
    all_unreachable: bool = False
    representative_id: str = "rep-1"
    finding_ids: list = field(default_factory=list)
    confidence: str = "High confidence"
    rule_signature: str = "rule:x"


def test_deterministic_fallback_when_provider_null(monkeypatch):
    from worker.ai import priority as pri
    monkeypatch.setattr(pri, "get_provider", lambda: type("p", (), {"name": "null"})())

    clusters = [
        FakeCluster(key="k1", severity="Critical", instances=4, kev=True),
        FakeCluster(key="k2", severity="High", instances=2),
        FakeCluster(key="k3", severity="Low", instances=1, all_unreachable=True),
    ]
    out = pri.build_priority_list(clusters, top_k=8)
    keys = [item["cluster_key"] for item in out]
    # all_unreachable cluster filtered out; Critical comes first
    assert keys == ["k1", "k2"]
    assert "kev match" in out[0]["reason"].lower()
    assert "callsites" in out[0]["reason"]


def test_empty_clusters_returns_empty(monkeypatch):
    from worker.ai import priority as pri
    monkeypatch.setattr(pri, "get_provider", lambda: type("p", (), {"name": "anthropic"})())
    assert pri.build_priority_list([], top_k=8) == []


class _FakeProvider:
    name = "anthropic"
    def __init__(self, payload):
        self._payload = payload
    def complete_json(self, system, user, schema, max_tokens, temperature):
        return self._payload


def test_llm_path_filters_hallucinated_keys(monkeypatch):
    from worker.ai import priority as pri
    payload = {
        "priorities": [
            {"cluster_key": "k1", "reason": "Highest severity and KEV-matched."},
            {"cluster_key": "fake-key", "reason": "the LLM made this up"},
            {"cluster_key": "k2", "reason": "Lower severity but more callsites."},
        ]
    }
    monkeypatch.setattr(pri, "get_provider", lambda: _FakeProvider(payload))
    clusters = [FakeCluster(key="k1"), FakeCluster(key="k2")]
    out = pri.build_priority_list(clusters)
    keys = [i["cluster_key"] for i in out]
    assert keys == ["k1", "k2"]
    assert "fake-key" not in keys


def test_llm_path_dedupes_repeated_keys(monkeypatch):
    from worker.ai import priority as pri
    payload = {
        "priorities": [
            {"cluster_key": "k1", "reason": "one"},
            {"cluster_key": "k1", "reason": "two"},
        ]
    }
    monkeypatch.setattr(pri, "get_provider", lambda: _FakeProvider(payload))
    out = pri.build_priority_list([FakeCluster(key="k1")])
    assert len(out) == 1
    assert out[0]["reason"] == "one"


def test_llm_failure_falls_back_to_deterministic(monkeypatch):
    from worker.ai import priority as pri

    class _Boom:
        name = "anthropic"
        def complete_json(self, **kw):
            raise RuntimeError("network down")

    monkeypatch.setattr(pri, "get_provider", lambda: _Boom())
    clusters = [FakeCluster(key="k1", severity="Critical")]
    out = pri.build_priority_list(clusters)
    assert len(out) == 1
    assert out[0]["cluster_key"] == "k1"


def test_empty_llm_response_falls_back(monkeypatch):
    from worker.ai import priority as pri
    monkeypatch.setattr(pri, "get_provider", lambda: _FakeProvider({"priorities": []}))
    clusters = [FakeCluster(key="k1", severity="Critical")]
    out = pri.build_priority_list(clusters)
    # Deterministic fallback kicks in so the triage view stays useful.
    assert len(out) == 1
    assert out[0]["cluster_key"] == "k1"


def test_top_k_caps_output(monkeypatch):
    from worker.ai import priority as pri
    monkeypatch.setattr(pri, "get_provider", lambda: type("p", (), {"name": "null"})())
    clusters = [FakeCluster(key=f"k{i}", severity="High") for i in range(20)]
    out = pri.build_priority_list(clusters, top_k=5)
    assert len(out) == 5
