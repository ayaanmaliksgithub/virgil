"""The RAG retriever is a security-relevant function: if it returns nothing
the LLM has nothing to ground in, and the answer should fall back to a refusal.
"""
from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.ai.chat import retrieve


def _f(title, category, severity=Severity.MEDIUM):
    return Finding(
        dedupe_key="x",
        title=title,
        severity=severity,
        confidence=Confidence.MEDIUM,
        category=category,
        affected_files=[],
        affected_lines=[],
        evidence="",
        explanation="",
        source_tool=["semgrep"],
        status=Status.OPEN,
    )


def test_retrieve_finds_keyword_overlap():
    fs = [
        _f("Hardcoded AWS access key in source", "Secret Exposure", Severity.CRITICAL),
        _f("Permissive Dockerfile runs as root", "Infrastructure / IaC Misconfiguration"),
        _f("Open redirect via unvalidated next", "Open Redirect"),
    ]
    out = retrieve(fs, "tell me about exposed AWS keys")
    assert out
    assert out[0].title.startswith("Hardcoded AWS")


def test_retrieve_returns_top_k():
    fs = [_f(f"Issue {i}", "Injection") for i in range(20)]
    out = retrieve(fs, "issue", k=5)
    assert len(out) == 5


def test_retrieve_empty_query_returns_some():
    fs = [_f("a", "Injection"), _f("b", "Injection")]
    out = retrieve(fs, "")
    assert len(out) == 2


def test_retrieve_skips_unrelated():
    fs = [_f("Open redirect", "Open Redirect"), _f("CSRF middleware missing", "CSRF")]
    out = retrieve(fs, "what AWS secrets did you find?")
    assert out == []  # no overlap → empty


def test_retrieve_prefers_higher_severity_on_ties():
    fs = [
        _f("SQL injection in handler", "Injection", Severity.LOW),
        _f("SQL injection in handler 2", "Injection", Severity.CRITICAL),
    ]
    out = retrieve(fs, "sql injection")
    assert out[0].severity == Severity.CRITICAL.value or out[0].severity == Severity.CRITICAL
