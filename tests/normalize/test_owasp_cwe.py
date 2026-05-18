from worker.normalize.owasp_cwe import normalize_cve, normalize_cwe, normalize_owasp


def test_normalize_cwe_accepts_canonical():
    assert normalize_cwe("CWE-79") == "CWE-79"


def test_normalize_cwe_extracts_number():
    assert normalize_cwe("CWE-79: Cross-Site Scripting") == "CWE-79"


def test_normalize_cwe_rejects_garbage():
    assert normalize_cwe("not-a-cwe") is None
    assert normalize_cwe(None) is None


def test_normalize_cve():
    assert normalize_cve("CVE-2023-12345") == "CVE-2023-12345"
    assert normalize_cve("cve-2023-1") is None  # too short


def test_normalize_owasp_passthrough():
    assert "Broken Access Control" in (normalize_owasp("A01:2021", "Path Traversal") or "")


def test_normalize_owasp_from_category():
    assert "Cryptographic Failures" in (normalize_owasp(None, "Cryptography") or "")


def test_normalize_owasp_unmapped():
    assert normalize_owasp(None, "Code Quality / Security Smell") is None
