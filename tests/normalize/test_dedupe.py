from audit_core import AffectedLine, Confidence, Finding, Severity, Status
from worker.normalize.dedupe import dedupe, make_dedupe_key


def _f(tool, rule, file="a.py", line=10, severity=Severity.MEDIUM, conf=Confidence.MEDIUM):
    return Finding(
        dedupe_key=make_dedupe_key(rule, file, line, "snippet"),
        title=f"{tool}:{rule}",
        severity=severity,
        confidence=conf,
        category="Injection",
        affected_files=[file],
        affected_lines=[AffectedLine(file=file, start=line)],
        evidence="x",
        explanation="y",
        source_tool=[tool],
        status=Status.OPEN,
    )


def test_dedupe_merges_same_rule_same_location():
    a = _f("semgrep", "sql-injection", severity=Severity.MEDIUM, conf=Confidence.MEDIUM)
    b = _f("trivy", "sql-injection", severity=Severity.HIGH, conf=Confidence.MEDIUM)
    out = dedupe([a, b])
    assert len(out) == 1
    f = out[0]
    assert set(f.source_tool) == {"semgrep", "trivy"}
    # max severity wins
    assert f.severity == Severity.HIGH.value or f.severity == Severity.HIGH
    # cross-tool agreement → high confidence
    assert f.confidence == Confidence.HIGH.value or f.confidence == Confidence.HIGH


def test_dedupe_keeps_distinct_findings():
    a = _f("semgrep", "sql-injection", line=10)
    b = _f("semgrep", "xss", line=10)
    assert len(dedupe([a, b])) == 2


def test_dedupe_key_normalizes_rule_prefix():
    k1 = make_dedupe_key("secret/aws-access-token", "a.py", 1, "x")
    k2 = make_dedupe_key("aws-access-token", "a.py", 1, "x")
    assert k1 == k2
