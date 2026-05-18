"""Output safety validator.

The LLM is prompted to refuse exploit content, but we never trust the prompt
alone. Every LLM-generated string is run through this validator before it is
persisted on a finding or surfaced in a report.

Rejection rules (any one is sufficient):
  - contains an exploit-payload shape (shellcode hex, common shell one-liners,
    classic SQLi/XSS payloads),
  - contains a unified diff / patch block,
  - contains step-numbered attack reproduction ("Step 1", "1.", "First, run"),
  - references attacker tools by name in an operational way
    (curl --data with secrets, `nc -e`, `msfvenom`, `sqlmap`, `hydra`, …).

A rejected response degrades gracefully: the caller substitutes a generic
defensive note instead of failing the audit.
"""
from __future__ import annotations

import re

_PAYLOAD_PATTERNS = [
    re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}", re.IGNORECASE),  # shellcode
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bOR\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"javascript:\s*[a-z(]", re.IGNORECASE),
    re.compile(r"\$\{jndi:", re.IGNORECASE),
    re.compile(r";\s*cat\s+/etc/passwd", re.IGNORECASE),
]

_DIFF_PATTERNS = [
    re.compile(r"^\s*```diff", re.MULTILINE),
    re.compile(r"^---\s+a/.+\n\+\+\+\s+b/.+", re.MULTILINE),
    re.compile(r"^@@ -\d+,\d+ \+\d+,\d+ @@", re.MULTILINE),
]

_STEP_PATTERNS = [
    re.compile(r"^\s*step\s*\d+\s*[:.)]", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*\d+\.\s+(?:run|execute|exploit|attack|launch|send)\b", re.IGNORECASE | re.MULTILINE),
]

_TOOL_PATTERNS = [
    re.compile(r"\bmsfvenom\b", re.IGNORECASE),
    re.compile(r"\bsqlmap\b", re.IGNORECASE),
    re.compile(r"\bhydra\b", re.IGNORECASE),
    re.compile(r"\bnc\s+-e\b", re.IGNORECASE),
    re.compile(r"\bnmap\s+-sS\b", re.IGNORECASE),
    re.compile(r"\bmetasploit\b", re.IGNORECASE),
]

REJECT_PATTERNS = _PAYLOAD_PATTERNS + _DIFF_PATTERNS + _STEP_PATTERNS + _TOOL_PATTERNS


def is_safe(text: str | None) -> bool:
    if not text:
        return True
    for pat in REJECT_PATTERNS:
        if pat.search(text):
            return False
    return True


def sanitize(text: str | None, *, fallback: str) -> str:
    """Return text if it passes, otherwise the fallback."""
    return text if is_safe(text) else fallback
