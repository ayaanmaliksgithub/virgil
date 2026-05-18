"""Refresh priority list when suppressions change.

Suppressing a finding should make the cluster vanish from the top-K
priority queue immediately — leaving the original LLM-ranked list
intact would confuse triage ("why is the closed item still #1?").

We do NOT re-call the LLM on every suppression event — that's slow and
costs tokens. Instead this uses the deterministic ranking (severity ×
KEV × instance count) over current non-suppressed findings, so the
update is instant. The original LLM-ranked list is still available
from the audit's reporting phase; users who want a fresh LLM rerank
can re-run the audit.

Cluster-hint regeneration is NOT done here — hints need the repo on
disk, which the API doesn't have. Stale hints are fine: a hint
points at a shared module, not at the specific suppressed finding.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Audit, FindingRow
from app.services.clusters import cluster_findings
from app.services.lifecycle import suppression_keys

log = logging.getLogger(__name__)


def refresh_priority_list(db: Session, audit: Audit) -> None:
    """Regenerate the audit's priority list from current non-suppressed
    findings using the deterministic fallback (no LLM call).
    """
    try:
        # Local import — worker code lives in the worker package; both share
        # the same venv in compose so this is free at runtime.
        from worker.ai.priority import _deterministic_fallback  # noqa: PLC2701
    except ImportError:
        log.debug("worker.ai.priority unavailable, skipping refresh")
        return

    rows = db.execute(
        select(FindingRow).where(FindingRow.audit_id == audit.id)
    ).scalars().all()
    if not rows:
        _apply(audit, db, [])
        return

    suppressed = suppression_keys(db, audit.source_ref)
    visible = [r for r in rows if r.dedupe_key not in suppressed]
    clusters = cluster_findings(visible)
    priorities = _deterministic_fallback(clusters, top_k=8)
    _apply(audit, db, priorities)


def _apply(audit: Audit, db: Session, priorities: list[dict]) -> None:
    profile = dict(audit.profile or {})
    if priorities:
        profile["priority_list"] = priorities
    else:
        profile.pop("priority_list", None)
    audit.profile = profile
    db.commit()
