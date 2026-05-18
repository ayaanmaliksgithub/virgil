"""Redaction.

Two surfaces are protected:
  1. `evidence` stored on each finding (UI + DB),
  2. anything fed to the LLM (`safe_for_llm`).

Redaction is intentionally conservative: false positives are fine, leaking a
real secret into the report or the LLM prompt is not.
"""
from __future__ import annotations

import re

# Order matters: more-specific patterns first.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS access key
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA****************"),
    # AWS secret key (rough — base64-like 40 chars after `aws_secret`)
    (re.compile(r"(?i)(aws[_-]?secret(?:[_-]?access)?[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}"),
     r"\1=<redacted>"),
    # GitHub tokens
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "ghp_<redacted>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github_pat_<redacted>"),
    # Generic high-entropy "secret=..." / "token=..." / "password=..." / "api_key=..."
    (re.compile(r"(?i)\b(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"]?[^\s'\"\n,;}{]{6,}"),
     r"\1=<redacted>"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "<jwt-redacted>"),
    # Slack tokens
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<slack-token-redacted>"),
    # Google API keys
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "<google-api-key-redacted>"),
    # Private key blocks
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END[^-]+-----"),
     "<private-key-redacted>"),
    # RFC1918 / link-local IPs — strip from logs to avoid leaking internal topology
    (re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}\b"), "<internal-ip>"),
    # Absolute /home or /Users paths — host filesystem leak
    (re.compile(r"/(?:home|Users)/[^\s'\":,]+"), "<host-path>"),
]

_MAX_LEN = 600


def redact(text: str | None) -> str:
    if not text:
        return ""
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    if len(out) > _MAX_LEN:
        out = out[:_MAX_LEN] + "…"
    return out


def safe_for_llm(text: str | None) -> str:
    """Stricter version for LLM prompts. Same patterns, harder cap."""
    if not text:
        return ""
    out = redact(text)
    return out[:400]
