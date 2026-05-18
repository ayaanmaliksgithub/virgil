"""Threat-intel feeds: EPSS scores + CISA Known Exploited Vulnerabilities.

Runs as a Celery beat task daily (see celery_app.py). Feeds are pulled by the
worker process directly — never from inside the scanner sandbox, which is
--network=none. Result is upserted into the `threat_intel` table; the
normalization pipeline joins on CVE during the correlate phase.

Parsing functions take raw bytes so tests can exercise them without HTTP.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Iterable, Mapping

log = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class EpssRow:
    cve: str
    score: float
    percentile: float


@dataclass(frozen=True)
class KevRow:
    cve: str
    added: date | None
    due: date | None


def parse_epss_csv(content: bytes) -> list[EpssRow]:
    """Parse the EPSS daily CSV (gzipped or plain).

    The feed format is: an optional comment line starting with `#`, then a header
    row `cve,epss,percentile`, then one row per CVE. Rows with non-CVE-shaped
    keys or unparseable numbers are skipped — the feed is normally clean but we
    don't want a single bad row to kill the refresh.
    """
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)
    text = content.decode("utf-8", errors="replace")
    rows: list[EpssRow] = []
    reader = csv.reader(io.StringIO(text))
    header_seen = False
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if not header_seen:
            # First non-comment row should be the header; recognize it loosely.
            if row[0].lower() == "cve":
                header_seen = True
                continue
            header_seen = True  # no header — treat as data
        if len(row) < 3:
            continue
        cve = row[0].strip().upper()
        if not _CVE_RE.match(cve):
            continue
        try:
            score = float(row[1])
            pct = float(row[2])
        except ValueError:
            continue
        if not (0.0 <= score <= 1.0 and 0.0 <= pct <= 1.0):
            continue
        rows.append(EpssRow(cve=cve, score=score, percentile=pct))
    return rows


def parse_kev_json(content: bytes) -> list[KevRow]:
    """Parse the CISA KEV catalog JSON.

    Schema: `{ "vulnerabilities": [ { "cveID", "dateAdded", "dueDate", ... }, ... ] }`.
    Dates use ISO-8601 (`YYYY-MM-DD`). Missing/bad dates become None — the
    boolean `kev=true` is the load-bearing signal.
    """
    try:
        doc = json.loads(content)
    except json.JSONDecodeError as e:
        log.warning("KEV feed not valid JSON: %s", e)
        return []
    entries = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return []
    rows: list[KevRow] = []
    for v in entries:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if not _CVE_RE.match(cve):
            continue
        rows.append(KevRow(cve=cve, added=_parse_iso_date(v.get("dateAdded")),
                           due=_parse_iso_date(v.get("dueDate"))))
    return rows


def _parse_iso_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def upsert_threat_intel(
    session,
    *,
    epss_rows: Iterable[EpssRow],
    kev_rows: Iterable[KevRow],
) -> tuple[int, int]:
    """Upsert EPSS + KEV rows into the `threat_intel` table.

    Returns `(epss_count, kev_count)`. KEV rows are unioned onto EPSS rows so a
    CVE present only in KEV (no EPSS score yet) still gets a row.
    """
    from sqlalchemy.dialects.postgresql import insert

    from app.db.models import ThreatIntel  # local import: avoids circular at module load

    now = datetime.now(timezone.utc)

    # Merge by CVE so we issue one INSERT per CVE rather than two competing rows.
    merged: dict[str, dict] = {}
    epss_count = 0
    for r in epss_rows:
        merged[r.cve] = {
            "cve": r.cve,
            "epss_score": r.score,
            "epss_percentile": r.percentile,
            "kev": False,
            "kev_added_date": None,
            "kev_due_date": None,
            "updated_at": now,
        }
        epss_count += 1

    kev_count = 0
    for r in kev_rows:
        existing = merged.get(r.cve)
        if existing is None:
            merged[r.cve] = {
                "cve": r.cve,
                "epss_score": None,
                "epss_percentile": None,
                "kev": True,
                "kev_added_date": r.added,
                "kev_due_date": r.due,
                "updated_at": now,
            }
        else:
            existing["kev"] = True
            existing["kev_added_date"] = r.added
            existing["kev_due_date"] = r.due
        kev_count += 1

    if not merged:
        return (0, 0)

    stmt = insert(ThreatIntel).values(list(merged.values()))
    stmt = stmt.on_conflict_do_update(
        index_elements=[ThreatIntel.cve],
        set_={
            "epss_score": stmt.excluded.epss_score,
            "epss_percentile": stmt.excluded.epss_percentile,
            "kev": stmt.excluded.kev,
            "kev_added_date": stmt.excluded.kev_added_date,
            "kev_due_date": stmt.excluded.kev_due_date,
            "updated_at": stmt.excluded.updated_at,
        },
    )
    session.execute(stmt)
    session.commit()
    return (epss_count, kev_count)


def lookup_many(session, cves: Iterable[str]) -> Mapping[str, "ThreatIntel"]:  # type: ignore[name-defined]
    """Batch-fetch ThreatIntel rows by CVE. Returns CVE → row, omitting misses."""
    from app.db.models import ThreatIntel

    seen: set[str] = set()
    normalized: list[str] = []
    for cve in cves:
        if not cve:
            continue
        key = cve.strip().upper()
        if key not in seen and _CVE_RE.match(key):
            seen.add(key)
            normalized.append(key)
    if not normalized:
        return {}
    rows = session.execute(
        ThreatIntel.__table__.select().where(ThreatIntel.cve.in_(normalized))
    ).fetchall()
    return {r.cve: r for r in rows}


def fetch_and_refresh(session, *, http_client=None) -> tuple[int, int]:
    """Pull both feeds and upsert. Returns `(epss_count, kev_count)`.

    `http_client` is injectable for tests. In prod we lazy-import httpx so the
    module imports cleanly in environments where httpx isn't installed (the
    HTTP path only runs from the beat-scheduled task).
    """
    if http_client is None:
        import httpx  # lazy; not a hard module-load dep
        http_client = httpx.Client(timeout=60.0, follow_redirects=True)
        owns_client = True
    else:
        owns_client = False

    try:
        epss_resp = http_client.get(EPSS_URL)
        epss_resp.raise_for_status()
        kev_resp = http_client.get(KEV_URL)
        kev_resp.raise_for_status()
        epss_rows = parse_epss_csv(epss_resp.content)
        kev_rows = parse_kev_json(kev_resp.content)
    finally:
        if owns_client:
            http_client.close()

    return upsert_threat_intel(session, epss_rows=epss_rows, kev_rows=kev_rows)
