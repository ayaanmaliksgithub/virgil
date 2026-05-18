"""PR-mode finding filter (Phase 4 §17 #5).

When an audit was created with `base_sha`/`head_sha`, we run the full
scanner suite as normal — restricting scanner inputs would force every
adapter to grow a "files of interest" knob, and Semgrep/Gitleaks
actually need surrounding files for some rules (taint flow, repo-wide
secrets). Instead we filter *after* normalization: keep only findings
whose `affected_lines` touch a line that the diff added or changed on
the head side.

This module is pure so the unified-diff parser + intersection logic
can be unit-tested without git or docker.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from audit_core import Finding

log = logging.getLogger(__name__)

# `@@ -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@` — we only
# care about the new-side range because findings are reported against
# head-tree line numbers.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    """Map head-side file path → set of changed line numbers.

    Handles `--git a/foo b/foo` headers, renames (`rename to bar`),
    deletions (head path goes to `/dev/null`), and multiple hunks per
    file. Lines beginning with `+` count; context (` `) and removals
    (`-`) do not.
    """
    by_file: dict[str, set[int]] = {}
    current_file: str | None = None
    new_lineno: int | None = None

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            tag = raw[4:].strip()
            if tag in ("/dev/null", ""):
                current_file = None
                new_lineno = None
                continue
            # strip leading "b/" added by `git diff`
            current_file = tag[2:] if tag.startswith("b/") else tag
            by_file.setdefault(current_file, set())
            new_lineno = None
        elif raw.startswith("@@") and current_file is not None:
            m = _HUNK_RE.match(raw)
            if not m:
                new_lineno = None
                continue
            new_lineno = int(m.group(1))
        elif new_lineno is not None and current_file is not None:
            if raw.startswith("+") and not raw.startswith("+++"):
                by_file[current_file].add(new_lineno)
                new_lineno += 1
            elif raw.startswith(" "):
                new_lineno += 1
            # `-` lines don't advance the new-side counter.

    # Drop files that ended up with no added lines (pure deletions).
    return {f: lines for f, lines in by_file.items() if lines}


def filter_findings_by_diff(
    findings: Iterable[Finding], changed: dict[str, set[int]]
) -> list[Finding]:
    """Keep findings that overlap the diff on head-side line ranges.

    A finding without any `affected_lines` falls back to a file-only
    match (any change to one of its `affected_files` keeps it). This is
    deliberately permissive — better to surface a repo-wide finding
    (e.g. dependency CVE) than to silently drop it in PR-mode.
    """
    out: list[Finding] = []
    for f in findings:
        if not f.affected_lines:
            if any(_file_in_diff(af, changed) for af in (f.affected_files or [])):
                out.append(f)
            continue

        kept = False
        for al in f.affected_lines:
            changed_lines = _match_file(al.file, changed)
            if not changed_lines:
                continue
            start = al.start
            end = al.end if al.end is not None else al.start
            if any(line in changed_lines for line in range(start, end + 1)):
                kept = True
                break
        if kept:
            out.append(f)
    return out


def _match_file(path: str, changed: dict[str, set[int]]) -> set[int] | None:
    """Resolve a finding's reported path against the diff keys.

    Scanners report paths relative to the scan root (`/repo`), which matches
    git's output. We fall back to a basename-suffix match for adapters that
    occasionally emit absolute or otherwise-prefixed paths.
    """
    if path in changed:
        return changed[path]
    for k, v in changed.items():
        if k.endswith(path) or path.endswith(k):
            return v
    return None


def _file_in_diff(path: str, changed: dict[str, set[int]]) -> bool:
    return _match_file(path, changed) is not None


def compute_changed_lines(
    repo_path: Path, base_sha: str, head_sha: str, *, timeout_sec: int = 60
) -> dict[str, set[int]]:
    """Run `git diff -U0 base..head` inside the scanner container.

    We re-enter the sandbox image (it bakes `git`) with read-only access
    to the repo to keep the diff computation off the host path.
    """
    image = os.environ.get("SCANNER_IMAGE", "virgil/scanner:latest")
    runtime = os.environ.get("CONTAINER_RUNTIME", "docker")
    if shutil.which(runtime) is None:
        log.warning("container runtime %r missing — PR-mode falling back to host git", runtime)
        cmd = ["git", "-C", str(repo_path), "diff", "-U0", f"{base_sha}..{head_sha}"]
    else:
        cmd = [
            runtime, "run", "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--network=none",
            "--user", "65534:65534",
            "-v", f"{repo_path}:/repo:ro",
            image,
            "git", "-C", "/repo", "diff", "-U0", f"{base_sha}..{head_sha}",
        ]
    try:
        proc = subprocess.run(cmd, timeout=timeout_sec, capture_output=True, text=True, check=False)
    except subprocess.TimeoutExpired:
        log.warning("git diff exceeded %ss in PR-mode; returning empty diff", timeout_sec)
        return {}
    if proc.returncode != 0:
        log.warning("git diff failed in PR-mode: %s", proc.stderr.strip()[:300])
        return {}
    return parse_unified_diff(proc.stdout)
