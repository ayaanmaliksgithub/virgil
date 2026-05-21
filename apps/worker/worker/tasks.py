"""Phase-based orchestration of an audit job.

State machine:
    queued → cloning → analyzing → scanning → correlating → reporting → completed
                                                                     └► failed

Each phase writes a checkpoint event so failures are observable. Anything
unexpected becomes a failed audit with a redacted error message — host
filesystem paths and stack traces never leak to the API surface.
"""
from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from sqlalchemy import delete

from app.db.models import Audit, FindingRow, JobEvent, Report
from app.services.reports import build_executive, build_technical, render_markdown
from app.services.storage import put_report
from app.security.secrets import decrypt_secret
from audit_core import AuditPhase, AuditState, Finding

from worker.ai.enrich import enrich_findings
from worker.ai.narrative import build_narrative
from worker.celery_app import celery_app
from worker.clone import CloneError, clone_repo
from worker.config import get_settings
from worker.db import SessionLocal
from worker.normalize import normalize_findings
from worker.normalize.threat_intel import enrich_with_threat_intel
from worker.profile import build_profile
from worker.sandbox import SandboxError, UnsafeArchive, run_scanner, safe_extract
from worker.scanners import ALL_ADAPTERS

log = logging.getLogger(__name__)


@celery_app.task(name="worker.tasks.run_audit", bind=True, max_retries=0)
def run_audit(self, audit_id: str) -> None:
    settings = get_settings()
    work_root = Path(settings.work_root)
    work_dir = work_root / audit_id
    repo_dir = work_dir / "repo"
    out_dir = work_dir / "out"

    try:
        with SessionLocal() as db:
            audit = db.get(Audit, UUID(audit_id))
            if audit is None:
                log.warning("audit %s not found, dropping task", audit_id)
                return
            audit.state = AuditState.RUNNING.value
            audit.started_at = datetime.now(timezone.utc)
            db.commit()

            _phase(db, audit, AuditPhase.CLONING, "Provisioning workspace")
            work_dir.mkdir(parents=True, exist_ok=True)
            _materialize_source(audit, work_dir, repo_dir)

            _phase(db, audit, AuditPhase.ANALYZING, "Detecting languages and frameworks")
            profile = build_profile(repo_dir)
            audit.profile = profile.model_dump()
            db.commit()

            _phase(db, audit, AuditPhase.SCANNING, "Running scanners in sandbox")
            raw_findings = []
            for AdapterCls in ALL_ADAPTERS:
                adapter = AdapterCls()
                if not adapter.applicable(profile):
                    continue
                tool_out = out_dir / adapter.name
                tool_out.mkdir(parents=True, exist_ok=True)
                # Adapters that need to inspect the host filesystem (e.g.
                # gitleaks checking for a `.git` directory to choose history
                # vs file-tree mode) read this attribute. Adapters that don't
                # need it simply ignore it.
                if hasattr(adapter, "host_repo_path"):
                    adapter.host_repo_path = repo_dir
                cmd = adapter.command(Path("/repo"), Path("/out"))
                extra_mounts = list(getattr(adapter, "extra_mounts", []) or [])
                try:
                    res = run_scanner(
                        cmd, repo_dir, out_dir / adapter.name, extra_mounts=extra_mounts,
                    )
                    _event(db, audit, AuditPhase.SCANNING,
                           f"{adapter.name} finished rc={res.returncode}",
                           level="info" if res.returncode == 0 else "warning")
                except SandboxError as e:
                    _event(db, audit, AuditPhase.SCANNING,
                           f"{adapter.name} sandbox error: {e}", level="error")
                    continue
                raw_findings.extend(adapter.parse(out_dir / adapter.name))

            _phase(db, audit, AuditPhase.CORRELATING,
                   f"Normalizing {len(raw_findings)} raw findings")
            normalized: list[Finding] = normalize_findings(raw_findings, audit.id)

            # §17 #5 — PR-mode filter: keep only findings whose head-side lines
            # were added/changed between base_sha..head_sha.
            if audit.base_sha and audit.head_sha:
                from worker.pr_mode import compute_changed_lines, filter_findings_by_diff

                changed = compute_changed_lines(repo_dir, audit.base_sha, audit.head_sha)
                before = len(normalized)
                normalized = filter_findings_by_diff(normalized, changed)
                _event(db, audit, AuditPhase.CORRELATING,
                       f"PR-mode: kept {len(normalized)}/{before} findings "
                       f"({len(changed)} changed files)")

            normalized = enrich_with_threat_intel(normalized, db)
            kev_hits = sum(1 for f in normalized if f.kev)
            if kev_hits:
                _event(db, audit, AuditPhase.CORRELATING,
                       f"Threat-intel: {kev_hits} CISA KEV match(es)")

            # §17 #7 — compliance control mapping. Pure static table, no DB hit.
            from worker.normalize.compliance import enrich_with_compliance
            normalized = enrich_with_compliance(normalized)

            # §17 #8 — reachability filter. Walks the source tree, marks dep
            # CVEs in unimported packages as `reachable=False` and demotes
            # their severity one rung. Operator-visible counts go to the
            # phase log so the noise reduction is auditable per scan.
            from worker.normalize.reachability import enrich_with_reachability
            normalized, reach_stats = enrich_with_reachability(normalized, repo_dir)
            if reach_stats["checked"]:
                _event(db, audit, AuditPhase.CORRELATING,
                       f"Reachability: {reach_stats['unreachable']} unreachable / "
                       f"{reach_stats['reachable']} reachable / "
                       f"{reach_stats['abstained']} abstained "
                       f"(of {reach_stats['checked']} dep findings)")

            # Code context: read the file slice around each finding (~30 lines)
            # and attach it redacted to the finding. The chat retriever uses
            # this so answers can reference actual code, not just metadata.
            from worker.normalize.code_context import enrich_with_code_context
            normalized = enrich_with_code_context(normalized, repo_dir)

            _phase(db, audit, AuditPhase.REPORTING, f"Enriching {len(normalized)} findings via LLM")
            # Throttled progress callback: log every Nth finding so the console
            # shows a live counter instead of staring at "reporting" for minutes.
            _enrich_total = len(normalized)
            _enrich_step = max(1, _enrich_total // 10)  # ~10 ticks across the loop
            def _enrich_progress(i: int, total: int):
                if i == 1 or i == total or i % _enrich_step == 0:
                    _event(db, audit, AuditPhase.REPORTING,
                           f"Enriching findings: {i}/{total}", level="info")
            try:
                normalized = enrich_findings(normalized, profile=profile, progress_cb=_enrich_progress)
                _event(db, audit, AuditPhase.REPORTING,
                       f"Enrichment complete — {_enrich_total} findings", level="info")
            except Exception as e:  # LLM is best-effort; never block the audit
                _event(db, audit, AuditPhase.REPORTING,
                       f"LLM enrichment skipped: {type(e).__name__}", level="warning")
            _event(db, audit, AuditPhase.REPORTING, "Writing audit narrative", level="info")
            try:
                narrative = build_narrative(normalized, profile=profile)
                if narrative:
                    audit.profile = {**(audit.profile or {}), "narrative": narrative}
            except Exception as e:
                _event(db, audit, AuditPhase.REPORTING,
                       f"Narrative skipped: {type(e).__name__}", level="warning")

            audit.finished_at = datetime.now(timezone.utc)
            persisted = _persist_findings(db, audit, normalized)

            # Triage layer — cluster the persisted findings and ask the LLM
            # to rank-order the top-K with a one-line rationale per item.
            # Stashed on audit.profile so the API serves it without re-calling
            # the LLM on every page view; deterministic fallback when the
            # provider is unavailable.
            try:
                from app.services.clusters import cluster_findings
                from worker.ai.priority import build_priority_list
                from worker.normalize.helpers import build_cluster_hint

                clusters = cluster_findings(persisted)
                priorities = build_priority_list(clusters, profile=profile, top_k=8)

                # Fix-the-helper hints — for each cluster with multiple
                # callsites, find the shared directory and shared internal
                # imports so the UI can point at the upstream module.
                hints: dict[str, dict] = {}
                for c in clusters:
                    if c.instances >= 2:
                        h = build_cluster_hint(c.files, repo_dir)
                        if h["shared_dir"] or h["shared_modules"]:
                            hints[c.key] = h

                update: dict = {}
                if priorities:
                    update["priority_list"] = priorities
                if hints:
                    update["cluster_hints"] = hints
                if update:
                    audit.profile = {**(audit.profile or {}), **update}
                if priorities:
                    _event(db, audit, AuditPhase.REPORTING,
                           f"Priority list: {len(priorities)} clusters ranked")
                if hints:
                    _event(db, audit, AuditPhase.REPORTING,
                           f"Fix-the-helper hints: {len(hints)} clusters annotated")
            except Exception as e:
                _event(db, audit, AuditPhase.REPORTING,
                       f"Priority list skipped: {type(e).__name__}", level="warning")

            _persist_report_artifacts(db, audit, persisted)
            _persist_sboms(db, audit, repo_dir, out_dir)

            # §17 #4 — auto-pick the previous succeeded audit of the same source_ref
            # as the baseline so the findings ledger renders new/recurring on first
            # paint of a re-scan. Only sets if not already set; user can override
            # via PATCH /v1/audits/{id}/baseline.
            if audit.baseline_audit_id is None:
                from app.services.lifecycle import autoselect_baseline

                prev = autoselect_baseline(db, audit)
                if prev is not None:
                    audit.baseline_audit_id = prev.id
                    _event(db, audit, AuditPhase.COMPLETED,
                           f"Baseline auto-selected: audit {prev.id}")

            audit.phase = AuditPhase.COMPLETED.value
            audit.state = AuditState.SUCCEEDED.value
            db.commit()
            _event(db, audit, AuditPhase.COMPLETED, f"Audit complete — {len(normalized)} findings")

            # Phase 5 — best-effort outbound webhook. Failures never affect
            # audit state; notifications.py logs and returns.
            try:
                from worker.notifications import notify_audit_completed

                notify_audit_completed(audit, persisted)
            except Exception as e:
                log.warning("notify_audit_completed raised %s — swallowed", type(e).__name__)

    except Exception as e:
        log.exception("audit %s failed", audit_id)
        with SessionLocal() as db:
            audit = db.get(Audit, UUID(audit_id))
            if audit is not None:
                audit.state = AuditState.FAILED.value
                audit.phase = AuditPhase.FAILED.value
                audit.error = _safe_error(e)
                audit.finished_at = datetime.now(timezone.utc)
                db.commit()
                _event(db, audit, AuditPhase.FAILED, _safe_error(e), level="error")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ---- helpers ---------------------------------------------------------------


def _materialize_source(audit: Audit, work_dir: Path, repo_dir: Path) -> None:
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    if audit.source_kind == "url":
        try:
            sha = clone_repo(audit.source_ref, work_dir, github_token=_github_token_for_audit(audit))
            audit.sha = sha or None
        except CloneError as e:
            raise RuntimeError(f"clone failed: {e}") from e
        # clone_repo lands the tree at work_dir/repo, which is repo_dir.
    elif audit.source_kind == "zip":
        zip_path = Path(audit.source_ref)
        if not zip_path.is_file():
            raise RuntimeError("uploaded archive missing on disk")
        try:
            safe_extract(zip_path, repo_dir)
        except UnsafeArchive as e:
            raise RuntimeError(f"unsafe archive: {e}") from e
    else:
        raise RuntimeError(f"unknown source kind: {audit.source_kind!r}")


def _github_token_for_audit(audit: Audit) -> str | None:
    for secret in audit.secrets or []:
        if secret.kind == "github_token":
            return decrypt_secret(secret.encrypted_value)
    return None


def _persist_findings(db, audit: Audit, findings: list[Finding]) -> list[FindingRow]:
    rows = [
        FindingRow(
            id=f.id,
            audit_id=audit.id,
            dedupe_key=f.dedupe_key,
            title=f.title,
            severity=f.severity if isinstance(f.severity, str) else f.severity.value,
            confidence=f.confidence if isinstance(f.confidence, str) else f.confidence.value,
            category=f.category,
            owasp_category=f.owasp_category,
            cwe=f.cwe,
            cve=f.cve,
            affected_files=f.affected_files,
            affected_lines=[al.model_dump() for al in f.affected_lines],
            evidence=f.evidence,
            explanation=f.explanation,
            exploitability_summary=f.exploitability_summary,
            business_impact=f.business_impact,
            safe_guidance=f.safe_guidance,
            source_tool=f.source_tool,
            raw_reference=f.raw_reference,
            epss_score=f.epss_score,
            epss_percentile=f.epss_percentile,
            kev=f.kev,
            compliance=f.compliance,
            reachable=f.reachable,
            code_context=f.code_context,
            status=f.status if isinstance(f.status, str) else f.status.value,
            created_at=f.created_at,
        )
        for f in findings
    ]
    db.bulk_save_objects(rows)
    db.commit()
    return rows


def _persist_report_artifacts(db, audit: Audit, findings: list[FindingRow]) -> None:
    """Pre-bake report artifacts into object storage and track their URIs.

    The API can still render reports on demand, so storage is deliberately
    best-effort. A scanner run should not be marked failed just because MinIO
    is down during local development.
    """
    reports: list[tuple[str, str, bytes]] = []
    for view, payload in (
        ("executive", build_executive(audit, findings)),
        ("technical", build_technical(audit, findings)),
    ):
        reports.append((view, "json", json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")))
        reports.append((view, "md", render_markdown(payload, view).encode("utf-8")))
        try:
            from app.services.pdf import render_pdf

            reports.append((view, "pdf", render_pdf(payload, view)))
        except Exception as e:
            _event(
                db,
                audit,
                AuditPhase.REPORTING,
                f"{view} PDF artifact skipped: {type(e).__name__}",
                level="warning",
            )

    stored = 0
    for view, fmt, body in reports:
        try:
            obj = put_report(str(audit.id), view, fmt, body)
        except Exception as e:
            _event(
                db,
                audit,
                AuditPhase.REPORTING,
                f"{view}.{fmt} artifact storage skipped: {type(e).__name__}",
                level="warning",
            )
            continue
        db.execute(
            delete(Report).where(
                Report.audit_id == audit.id,
                Report.kind == view,
                Report.format == fmt,
            )
        )
        db.add(Report(audit_id=audit.id, kind=view, format=fmt, uri=obj.uri))
        stored += 1

    if stored:
        db.commit()
        _event(db, audit, AuditPhase.REPORTING, f"Stored {stored} report artifact(s)")


def _persist_sboms(db, audit: Audit, repo_dir: Path, out_root: Path) -> None:
    """Generate CycloneDX + SPDX SBOMs via Trivy and persist them as
    `reports(kind="sbom", format=<variant>)` rows pointing at object storage.

    Best-effort: a missing container runtime, a Trivy failure, or storage
    outage all log and continue. SBOM artifacts are surfaced as download
    options on the report page when present; their absence is a soft gap,
    never a reason to fail the audit.
    """
    from worker.sbom import generate_sboms

    sbom_out = out_root / "sbom"
    try:
        artifacts = generate_sboms(repo_dir, sbom_out)
    except Exception as e:
        _event(db, audit, AuditPhase.REPORTING,
               f"SBOM generation skipped: {type(e).__name__}", level="warning")
        return
    if not artifacts:
        return

    stored = 0
    for variant, body in artifacts.items():
        try:
            obj = put_report(str(audit.id), "sbom", variant, body)
        except Exception as e:
            _event(db, audit, AuditPhase.REPORTING,
                   f"sbom.{variant} storage skipped: {type(e).__name__}", level="warning")
            continue
        db.execute(
            delete(Report).where(
                Report.audit_id == audit.id,
                Report.kind == "sbom",
                Report.format == variant,
            )
        )
        db.add(Report(audit_id=audit.id, kind="sbom", format=variant, uri=obj.uri))
        stored += 1
    if stored:
        db.commit()
        _event(db, audit, AuditPhase.REPORTING, f"Stored {stored} SBOM artifact(s)")


def _phase(db, audit: Audit, phase: AuditPhase, message: str) -> None:
    audit.phase = phase.value
    db.commit()
    _event(db, audit, phase, message)


def _event(db, audit: Audit, phase: AuditPhase, message: str, *, level: str = "info") -> None:
    db.add(JobEvent(audit_id=audit.id, phase=phase.value, level=level, message=message[:2000]))
    db.commit()


def _safe_error(e: Exception) -> str:
    # Strip host paths and any stack-trace details from anything the user might see.
    msg = f"{type(e).__name__}: {e}"
    msg = msg.replace("/Users/", "<host>/").replace("/home/", "<host>/")
    return msg[:500]


@celery_app.task(name="worker.tasks.refresh_threat_intel", bind=True, max_retries=0)
def refresh_threat_intel(self) -> dict[str, int]:
    """Nightly: pull EPSS + CISA KEV and upsert into `threat_intel`.

    Returns counts so beat logs can show what landed. Never raises on a feed
    error — the next run will try again, and findings without enrichment still
    flow through the pipeline correctly.
    """
    from worker.threat_intel import fetch_and_refresh

    try:
        with SessionLocal() as db:
            epss_count, kev_count = fetch_and_refresh(db)
            log.info("threat_intel refreshed: epss=%d kev=%d", epss_count, kev_count)
            return {"epss": epss_count, "kev": kev_count}
    except Exception as e:
        log.warning("threat_intel refresh failed: %s", _safe_error(e))
        return {"epss": 0, "kev": 0, "error": type(e).__name__}
