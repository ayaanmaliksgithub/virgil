"""API-side redaction. Re-exports the worker's redactor so the API and worker
agree on what counts as a secret. The redactor lives in audit_core in spirit;
for now we duplicate to keep package boundaries clean — keep the patterns in
worker/normalize/redact.py as the source of truth and update both together.
"""
from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA****************"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "ghp_<redacted>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github_pat_<redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "<jwt-redacted>"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<slack-token-redacted>"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "<google-api-key-redacted>"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END[^-]+-----"),
     "<private-key-redacted>"),
]


def redact(text: str) -> str:
    if not text:
        return ""
    out = text
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out
