"""End-to-end normalization: RawFinding[] -> Finding[] (with dedupe + redaction)."""
from audit_core import RawFinding, Severity
from worker.normalize import normalize_findings


def _raw(tool, rule, file="app.py", line=10, snippet=None, sev=None, cve=None, cwe=None, owasp=None):
    return RawFinding(
        source_tool=tool, rule_id=rule, title=f"{tool}:{rule}",
        raw_severity=sev, message="msg", file=file,
        start_line=line, snippet=snippet, cwe=cwe, cve=cve, owasp=owasp,
    )


def test_pipeline_dedupes_cross_tool():
    a = _raw("semgrep", "sql-injection", snippet="x = q + input", sev="ERROR")
    b = _raw("trivy", "sql-injection", snippet="x = q + input", sev="HIGH")
    findings = normalize_findings([a, b])
    assert len(findings) == 1
    f = findings[0]
    assert set(f.source_tool) == {"semgrep", "trivy"}
    assert f.severity == Severity.HIGH.value or f.severity == Severity.HIGH


def test_pipeline_redacts_evidence():
    rf = _raw("gitleaks", "aws-access-token", snippet="AKIAABCDEFGHIJKLMNOP")
    out = normalize_findings([rf])
    assert "AKIAABCDEFGHIJKLMNOP" not in out[0].evidence


def test_pipeline_assigns_owasp_for_secret():
    rf = _raw("gitleaks", "aws-access-token", snippet="token=…")
    f = normalize_findings([rf])[0]
    assert f.owasp_category is not None
    assert "Authentication" in f.owasp_category
