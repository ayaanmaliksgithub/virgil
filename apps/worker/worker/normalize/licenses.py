"""License risk classification.

Policy is selected by the `LICENSE_POLICY` env var:

- `permissive` (default) — strong copyleft (AGPL/SSPL/GPL) is High, weak
  copyleft (LGPL/MPL/EPL/CDDL) is Medium, unknown/missing is Medium with
  manual review, permissive licenses (MIT/BSD/Apache/...) are suppressed.
- `strict` — same copyleft policy, but unknown/missing is escalated to High.
  Right for audit programs that want zero unidentified dependencies.
- `copyleft-only` — only AGPL/SSPL emits a finding (High). Everything else is
  Informational at most. Right when license compliance is delegated elsewhere
  and we only want the legally-loudest items in the audit.

`classify_license` returns a Trivy-vocabulary severity string so the existing
severity mapper handles the rest of the pipeline without a new branch — or
`None` to suppress the finding entirely (permissive license under default
policy).
"""
from __future__ import annotations

import os
from typing import Iterable

# SPDX identifier sets. Match is case-insensitive; comparisons happen on the
# upper-cased string so users don't have to worry about casing in feed output.
_STRONG_COPYLEFT: frozenset[str] = frozenset({
    "AGPL-1.0", "AGPL-1.0-ONLY", "AGPL-1.0-OR-LATER",
    "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER",
    "SSPL-1.0",
    "GPL-1.0", "GPL-1.0-ONLY", "GPL-1.0-OR-LATER",
    "GPL-2.0", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER",
    "GPL-3.0", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
})

_WEAK_COPYLEFT: frozenset[str] = frozenset({
    "LGPL-2.0", "LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER",
    "LGPL-2.1", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER",
    "LGPL-3.0", "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
    "MPL-1.0", "MPL-1.1", "MPL-2.0",
    "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1",
    "OSL-3.0", "EUPL-1.1", "EUPL-1.2",
})

_PERMISSIVE: frozenset[str] = frozenset({
    "MIT", "MIT-0",
    "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE", "BSD-3-CLAUSE-CLEAR",
    "APACHE-1.1", "APACHE-2.0",
    "ISC", "UNLICENSE", "0BSD", "ZLIB", "WTFPL", "CC0-1.0", "BSL-1.0",
    "PYTHON-2.0", "POSTGRESQL",
})

VALID_POLICIES: frozenset[str] = frozenset({"permissive", "strict", "copyleft-only"})


def _resolve_policy(policy: str | None) -> str:
    raw = (policy or os.environ.get("LICENSE_POLICY", "permissive")).strip().lower()
    if raw not in VALID_POLICIES:
        return "permissive"
    return raw


def classify_license(name: str | None, *, policy: str | None = None) -> str | None:
    """Map an SPDX-ish license name to a Trivy-style severity, or None to suppress.

    Returns:
        `"HIGH"` / `"MEDIUM"` / `"INFORMATIONAL"` — fed to the existing
        severity mapper (Trivy table) downstream.
        `None` — finding should not be emitted (permissive license, no risk
        signal worth surfacing).
    """
    mode = _resolve_policy(policy)
    norm = (name or "").strip().upper()

    if mode == "copyleft-only":
        if norm in _STRONG_COPYLEFT:
            return "HIGH"
        if not norm:
            return "INFORMATIONAL"
        # Even weak copyleft is silenced under copyleft-only — but unknowns
        # stay informational so they appear somewhere in the report.
        if norm in _PERMISSIVE or norm in _WEAK_COPYLEFT:
            return None
        return "INFORMATIONAL"

    # permissive + strict share copyleft handling
    if norm in _STRONG_COPYLEFT:
        return "HIGH"
    if norm in _WEAK_COPYLEFT:
        return "MEDIUM"
    if norm in _PERMISSIVE:
        return None
    # Unknown / unrecognized / empty
    if mode == "strict":
        return "HIGH"
    return "MEDIUM"


def classify_many(names: Iterable[str | None], *, policy: str | None = None) -> list[str | None]:
    return [classify_license(n, policy=policy) for n in names]
