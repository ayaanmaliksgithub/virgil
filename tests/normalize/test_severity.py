import pytest
from audit_core import Severity
from worker.normalize.severity import map_severity


@pytest.mark.parametrize("tool,raw,expected", [
    ("semgrep", "ERROR", Severity.HIGH),
    ("semgrep", "WARNING", Severity.MEDIUM),
    ("semgrep", "INFO", Severity.INFORMATIONAL),
    ("trivy", "CRITICAL", Severity.CRITICAL),
    ("trivy", "UNKNOWN", Severity.INFORMATIONAL),
    ("gitleaks", "HIGH", Severity.HIGH),
    ("gitleaks", "LOW", Severity.MEDIUM),  # gitleaks LOW still meaningful
    ("semgrep", None, Severity.MEDIUM),
    ("unknown-tool", "HIGH", Severity.MEDIUM),
])
def test_map_severity(tool, raw, expected):
    assert map_severity(tool, raw) == expected
