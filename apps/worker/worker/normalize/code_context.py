"""Capture redacted code slices around each finding.

The ask-the-auditor chat only knows what we put in `_finding_blob`.
Without code, the LLM can describe a finding in the abstract but can't
say things like "this is fine because the input is already
parameterized two lines up" — which is exactly the kind of triage help
users want.

This module reads the file referenced by each finding's first
`affected_line`, extracts a ~30-line window centered on it, and stores
the redacted result on `finding.code_context`. Anything we can't read
(binary, encoding error, path outside repo) is skipped — the chat
degrades to metadata-only for that finding, same as today.

Security:
  * Reads are scoped to repo_path. Any resolved path that escapes is
    skipped.
  * Output runs through `safe_for_llm` so secret patterns and host
    paths are scrubbed before storage.
  * Hard size cap (2KB) so prompt budgets stay sane.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable

from audit_core import Finding

from worker.normalize.redact import redact

log = logging.getLogger(__name__)

CONTEXT_LINES_BEFORE = 12
CONTEXT_LINES_AFTER = 18
MAX_CONTEXT_BYTES = 2048


def _resolve_inside(repo: Path, candidate: str) -> Path | None:
    """Return the absolute path inside repo, or None if it escapes."""
    raw = (repo / candidate).resolve()
    try:
        raw.relative_to(repo.resolve())
    except ValueError:
        return None
    if not raw.is_file():
        return None
    return raw


def extract_slice(repo: Path, file_path: str, start_line: int) -> str | None:
    """Read a ~30-line slice centered on `start_line` (1-indexed).

    Returns the redacted text, or None if the file can't be read.
    """
    resolved = _resolve_inside(repo, file_path.lstrip("/"))
    if resolved is None:
        return None
    try:
        text = resolved.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    start = max(1, start_line - CONTEXT_LINES_BEFORE)
    end = min(len(lines), start_line + CONTEXT_LINES_AFTER)
    window = lines[start - 1 : end]

    # Render with 1-indexed line numbers so the LLM can refer to "line 42".
    # We redact line-by-line because `redact()` caps single calls at 600 chars
    # to defend the metadata-text path — applied to a multi-line code blob
    # that cap would silently chop the window. Per-line redaction keeps the
    # whole window while still scrubbing secret patterns.
    width = len(str(end))
    rendered_lines = [
        f"{(start + i):>{width}}  {redact(line)}" for i, line in enumerate(window)
    ]
    redacted = "\n".join(rendered_lines)
    if not redacted:
        return None
    if len(redacted.encode("utf-8")) > MAX_CONTEXT_BYTES:
        truncated = redacted.encode("utf-8")[:MAX_CONTEXT_BYTES]
        return truncated.decode("utf-8", errors="ignore") + "\n… (truncated)"
    return redacted


def enrich_with_code_context(findings: Iterable[Finding], repo_path: Path) -> list[Finding]:
    """Attach a redacted code slice to each finding when readable."""
    out: list[Finding] = []
    for f in findings:
        if not f.affected_lines:
            out.append(f)
            continue
        al = f.affected_lines[0]
        ctx = extract_slice(repo_path, al.file, al.start)
        if ctx is None:
            out.append(f)
            continue
        out.append(f.model_copy(update={"code_context": ctx}))
    return out
