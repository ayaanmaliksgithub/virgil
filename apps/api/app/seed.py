"""Seed a demo OWASP NodeGoat audit on a fresh database.

This module exists so that `git clone && docker compose up` lands on a
populated `localhost:3000` instead of an empty form. Every row is loaded
from `seed_data/nodegoat.json`; the only computation happens here are the
cluster_key hashes for the priority_list + cluster_hints (so they line up
with what `cluster_findings()` produces at request time).

Idempotency
-----------
The seed audit has a fixed UUID (`00000000-0000-0000-0000-000000000001`).
If a row with that ID already exists we skip — running this on a populated
DB is safe.

Disable
-------
Set `SEED_DEMO_AUDIT=false` in the environment to skip the seed entirely.

Run manually
------------
`python -m app.seed` from inside the api container, or `docker compose run
--rm api python -m app.seed` from the host.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from importlib import resources
from pathlib import Path
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import Audit, ChatMessage, ChatSession, FindingRow, JobEvent
from app.db.session import SessionLocal

log = logging.getLogger(__name__)

SEED_AUDIT_ID = UUID("00000000-0000-0000-0000-000000000001")
SEED_DATA_FILE = "nodegoat.json"


def _load_seed() -> dict:
    """Read the bundled JSON fixture, regardless of how the package is installed."""
    try:
        with resources.files("app.seed_data").joinpath(SEED_DATA_FILE).open("r", encoding="utf-8") as f:
            return json.load(f)
    except (ModuleNotFoundError, FileNotFoundError):
        # Fallback for editable installs where importlib.resources can't see
        # the data directory (rare but observed under uv). Try the on-disk path.
        local = Path(__file__).resolve().parent / "seed_data" / SEED_DATA_FILE
        with local.open("r", encoding="utf-8") as f:
            return json.load(f)


def _parse_dt(s: str | None) -> datetime | None:
    """JSON has ISO-8601 strings; SQLAlchemy wants real datetimes."""
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _cluster_key(category: str, cwe: str | None, rule_signature: str) -> str:
    """Reproduce `app.services.clusters._cluster_key` without importing it.

    Kept inline so the seed module has no circular-import risk with the
    services layer (services.clusters imports models, models will be loaded
    by the time seed runs — but the principle of fewest dependencies wins
    for boot-time code).
    """
    blob = "|".join([category or "uncategorized", cwe or "no-cwe", rule_signature])
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


def _resolve_triple(triple: str) -> str:
    """Turn a `category|cwe|rule_signature` triple from the JSON into a
    real cluster_key. The CWE part may be the sentinel `no-cwe` (when the
    finding genuinely has no CWE)."""
    parts = triple.split("|", 2)
    if len(parts) != 3:
        raise ValueError(f"bad cluster triple: {triple!r}")
    category, cwe, rule = parts
    if cwe == "no-cwe":
        cwe = None
    return _cluster_key(category, cwe, rule)


def _resolve_priority_list(template: dict) -> list[dict]:
    out = []
    for item in template.get("items", []):
        out.append({
            "cluster_key": _resolve_triple(item["triple"]),
            "reason": item["reason"],
        })
    return out


def _resolve_cluster_hints(template: dict) -> dict[str, dict]:
    out = {}
    for triple, hint in template.items():
        if triple.startswith("_"):
            continue
        out[_resolve_triple(triple)] = hint
    return out


def _make_dedupe_key(finding: dict) -> str:
    """Reproduces `worker.normalize.dedupe.make_dedupe_key` shape without
    importing the worker package — the seed is API-side, not worker-side,
    and dragging the worker import in would couple the boot path.
    """
    rule = (finding.get("raw_reference") or {}).get("check_id") \
        or (finding.get("raw_reference") or {}).get("rule_id") \
        or (finding.get("raw_reference") or {}).get("id") \
        or "seed"
    files = finding.get("affected_files") or []
    file = files[0] if files else ""
    lines = finding.get("affected_lines") or []
    start = lines[0]["start"] if lines else 1
    snippet = finding.get("evidence") or ""
    snippet_hash = hashlib.sha256(snippet.strip().encode()).hexdigest()[:12]
    base = f"{rule}|{file}|{start}|{snippet_hash}"
    return hashlib.sha256(base.encode()).hexdigest()[:24]


def _build_audit(data: dict) -> Audit:
    a = data["audit"]
    profile = dict(a.get("profile") or {})

    # Resolve the templated priority_list + cluster_hints into real keys.
    if "priority_list_template" in data:
        profile["priority_list"] = _resolve_priority_list(data["priority_list_template"])
    if "cluster_hints_template" in data:
        profile["cluster_hints"] = _resolve_cluster_hints(data["cluster_hints_template"])

    return Audit(
        id=UUID(a["id"]),
        source_kind=a["source_kind"],
        source_ref=a["source_ref"],
        sha=a.get("sha"),
        state=a["state"],
        phase=a["phase"],
        created_at=_parse_dt(a.get("created_at")),
        started_at=_parse_dt(a.get("started_at")),
        finished_at=_parse_dt(a.get("finished_at")),
        baseline_audit_id=UUID(a["baseline_audit_id"]) if a.get("baseline_audit_id") else None,
        base_sha=a.get("base_sha"),
        head_sha=a.get("head_sha"),
        profile=profile,
    )


def _build_findings(data: dict) -> list[FindingRow]:
    audit_id = UUID(data["audit"]["id"])
    rows = []
    for f in data.get("findings", []):
        rows.append(FindingRow(
            id=UUID(f["id"]),
            audit_id=audit_id,
            dedupe_key=_make_dedupe_key(f),
            title=f["title"],
            severity=f["severity"],
            confidence=f["confidence"],
            category=f["category"],
            owasp_category=f.get("owasp_category"),
            cwe=f.get("cwe"),
            cve=f.get("cve"),
            affected_files=f.get("affected_files") or [],
            affected_lines=f.get("affected_lines") or [],
            evidence=f["evidence"],
            explanation=f["explanation"],
            exploitability_summary=f.get("exploitability_summary"),
            business_impact=f.get("business_impact"),
            safe_guidance=f.get("safe_guidance"),
            source_tool=f.get("source_tool") or ["seed"],
            raw_reference=f.get("raw_reference") or {},
            epss_score=f.get("epss_score"),
            epss_percentile=f.get("epss_percentile"),
            kev=bool(f.get("kev")),
            compliance=f.get("compliance") or {},
            reachable=f.get("reachable"),
            code_context=f.get("code_context"),
            status=f.get("status", "open"),
            created_at=_parse_dt(f.get("created_at")),
        ))
    return rows


def _build_events(data: dict) -> list[JobEvent]:
    audit_id = UUID(data["audit"]["id"])
    rows = []
    for e in data.get("job_events", []):
        rows.append(JobEvent(
            audit_id=audit_id,
            phase=e["phase"],
            level=e.get("level", "info"),
            ts=_parse_dt(e.get("ts")),
            message=e["message"],
        ))
    return rows


def _build_chat(data: dict) -> tuple[ChatSession | None, list[ChatMessage]]:
    sess_blob = data.get("chat_session")
    if not sess_blob:
        return None, []
    audit_id = UUID(data["audit"]["id"])
    session = ChatSession(
        id=UUID(sess_blob["id"]),
        audit_id=audit_id,
    )
    msgs = []
    for m in sess_blob.get("messages", []):
        msgs.append(ChatMessage(
            id=UUID(m["id"]),
            session_id=session.id,
            role=m["role"],
            content=m["content"],
            citations=m.get("citations") or [],
        ))
    return session, msgs


def run(db: Session | None = None) -> bool:
    """Seed the demo audit. Returns True if seeded, False if skipped (already present).

    Accepts an explicit Session for tests; otherwise opens its own.
    """
    if os.environ.get("SEED_DEMO_AUDIT", "true").lower() in ("false", "0", "no", "off"):
        log.info("SEED_DEMO_AUDIT disabled; skipping demo seed")
        return False

    owns_session = db is None
    db = db or SessionLocal()
    try:
        existing = db.get(Audit, SEED_AUDIT_ID)
        if existing is not None:
            log.info("demo audit already present (id=%s); skipping seed", SEED_AUDIT_ID)
            return False

        data = _load_seed()
        audit = _build_audit(data)
        findings = _build_findings(data)
        events = _build_events(data)
        chat_session, chat_msgs = _build_chat(data)

        db.add(audit)
        db.flush()  # audit must exist before findings/events FK to it
        db.bulk_save_objects(findings)
        db.bulk_save_objects(events)
        if chat_session is not None:
            db.add(chat_session)
            db.flush()
            db.bulk_save_objects(chat_msgs)
        db.commit()

        log.info(
            "demo audit seeded: id=%s findings=%d events=%d chat_messages=%d",
            audit.id, len(findings), len(events), len(chat_msgs),
        )
        return True
    finally:
        if owns_session:
            db.close()


def main() -> None:
    """`python -m app.seed` entrypoint."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s :: %(message)s")
    seeded = run()
    sys.exit(0 if seeded or True else 1)  # success either way — skipping is a valid outcome


if __name__ == "__main__":
    main()
