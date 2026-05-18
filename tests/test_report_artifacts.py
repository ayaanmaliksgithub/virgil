from __future__ import annotations

import sys
import types
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("celery")
pytest.importorskip("boto3")

from app.db.models import Audit, FindingRow, JobEvent, Report
from worker import tasks


class FakeDB:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.executed: list[object] = []
        self.commits = 0

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def execute(self, stmt: object) -> None:
        self.executed.append(stmt)

    def commit(self) -> None:
        self.commits += 1


def _audit() -> Audit:
    return Audit(
        id=uuid4(),
        source_kind="url",
        source_ref="https://github.com/example/repo",
        state="running",
        phase="reporting",
        finished_at=datetime.now(timezone.utc),
        profile={"languages": {"Python": 3}},
    )


def _finding(audit: Audit) -> FindingRow:
    return FindingRow(
        id=uuid4(),
        audit_id=audit.id,
        dedupe_key="abc123",
        title="Hardcoded token",
        severity="High",
        confidence="High confidence",
        category="Secret Exposure",
        owasp_category="A02:2021 - Cryptographic Failures",
        cwe="CWE-798",
        cve=None,
        affected_files=["settings.py"],
        affected_lines=[{"file": "settings.py", "start": 12, "end": 12}],
        evidence="token=<redacted>",
        explanation="A credential-like value was committed.",
        exploitability_summary=None,
        business_impact="Possible unauthorized access.",
        safe_guidance="Rotate the credential and move it to managed storage.",
        source_tool=["gitleaks"],
        raw_reference={},
        status="open",
        created_at=datetime.now(timezone.utc),
    )


def test_persist_report_artifacts_writes_json_markdown_and_pdf(monkeypatch):
    audit = _audit()
    finding = _finding(audit)
    db = FakeDB()
    calls: list[tuple[str, str, bytes]] = []

    def fake_put_report(audit_id: str, view: str, fmt: str, body: bytes):
        calls.append((view, fmt, body))
        return SimpleNamespace(uri=f"s3://bucket/reports/{audit_id}/{view}.{fmt}")

    fake_pdf = types.ModuleType("app.services.pdf")
    fake_pdf.render_pdf = lambda payload, view: f"pdf:{view}".encode()

    monkeypatch.setitem(sys.modules, "app.services.pdf", fake_pdf)
    monkeypatch.setattr(tasks, "put_report", fake_put_report)

    tasks._persist_report_artifacts(db, audit, [finding])

    assert [(view, fmt) for view, fmt, _ in calls] == [
        ("executive", "json"),
        ("executive", "md"),
        ("executive", "pdf"),
        ("technical", "json"),
        ("technical", "md"),
        ("technical", "pdf"),
    ]
    reports = [obj for obj in db.added if isinstance(obj, Report)]
    assert len(reports) == 6
    assert len(db.executed) == 6
    assert {r.kind for r in reports} == {"executive", "technical"}
    assert {r.format for r in reports} == {"json", "md", "pdf"}
    assert any(b"Hardcoded token" in body for _, fmt, body in calls if fmt == "json")
    assert any(isinstance(obj, JobEvent) and "Stored 6 report artifact" in obj.message for obj in db.added)


def test_persist_report_artifacts_warns_when_storage_fails(monkeypatch):
    audit = _audit()
    finding = _finding(audit)
    db = FakeDB()

    fake_pdf = types.ModuleType("app.services.pdf")
    fake_pdf.render_pdf = lambda payload, view: f"pdf:{view}".encode()

    monkeypatch.setitem(sys.modules, "app.services.pdf", fake_pdf)
    monkeypatch.setattr(tasks, "put_report", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("down")))

    tasks._persist_report_artifacts(db, audit, [finding])

    assert not [obj for obj in db.added if isinstance(obj, Report)]
    assert not db.executed
    warnings = [obj for obj in db.added if isinstance(obj, JobEvent)]
    assert len(warnings) == 6
    assert all("artifact storage skipped: RuntimeError" in event.message for event in warnings)
