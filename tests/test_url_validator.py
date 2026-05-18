"""URL validator is a security boundary — exercises must enumerate every
disallowed shape we've seen attempted (SSRF, credential injection, scheme
smuggling, etc.).
"""
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))

from app.security.url_validator import InvalidRepoURL, validate_repo_url  # noqa: E402


def test_accepts_github_repo(monkeypatch):
    monkeypatch.setattr(
        "app.security.url_validator.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, "", ("140.82.112.3", 443))],
    )
    assert validate_repo_url("https://github.com/OWASP/NodeGoat") == "https://github.com/OWASP/NodeGoat"


def test_rejects_http():
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("http://github.com/a/b")


def test_rejects_credentials_in_url():
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("https://user:pass@github.com/a/b")
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("https://token@github.com/a/b")


def test_rejects_unlisted_host():
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("https://evil.example.com/a/b")


def test_rejects_missing_repo_path():
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("https://github.com/")
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("https://github.com/just-org")


def test_rejects_non_standard_port():
    with pytest.raises(InvalidRepoURL):
        validate_repo_url("https://github.com:8443/a/b")
