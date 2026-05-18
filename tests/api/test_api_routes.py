from __future__ import annotations

import socket
import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlalchemy")
pytest.importorskip("psycopg")
pytest.importorskip("celery")
pytest.importorskip("multipart")
pytest.importorskip("sse_starlette")
pytest.importorskip("cryptography")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Audit, AuditSecret, Base, FindingRow, Report
from app.db.session import get_db
from app.main import app


TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="set TEST_DATABASE_URL to a disposable Postgres database to run API integration tests",
)


@pytest.fixture()
def db_session():
    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True, future=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def client(db_session, monkeypatch):
    def override_db():
        yield db_session

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.3", 443))],
    )
    monkeypatch.setattr("app.routes.audits.enqueue_audit", lambda audit_id: None)
    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


def _audit(db_session) -> Audit:
    audit = Audit(
        id=uuid4(),
        source_kind="url",
        source_ref="https://github.com/example/repo",
        state="succeeded",
        phase="completed",
        finished_at=datetime.now(timezone.utc),
        profile={"languages": {"Python": 2}},
    )
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)
    return audit


def _finding(db_session, audit: Audit, *, severity: str = "High", category: str = "Secret Exposure") -> FindingRow:
    finding = FindingRow(
        id=uuid4(),
        audit_id=audit.id,
        dedupe_key=f"dedupe-{severity}-{category}",
        title=f"{severity} finding",
        severity=severity,
        confidence="High confidence",
        category=category,
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
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


def test_create_audit_json_validates_persists_and_enqueues(client, db_session, monkeypatch):
    enqueued: list[str] = []
    monkeypatch.setattr("app.routes.audits.enqueue_audit", enqueued.append)

    res = client.post("/v1/audits/json", json={"repo_url": "https://github.com/example/repo/"})

    assert res.status_code == 201
    body = res.json()
    assert body["source_kind"] == "url"
    assert body["source_ref"] == "https://github.com/example/repo"
    assert body["state"] == "pending"
    assert body["phase"] == "queued"
    assert enqueued == [body["id"]]
    assert db_session.get(Audit, body["id"]) is not None


def test_create_private_github_audit_stores_encrypted_token(client, db_session, monkeypatch):
    enqueued: list[str] = []
    monkeypatch.setattr("app.routes.audits.enqueue_audit", enqueued.append)
    monkeypatch.setattr("app.services.intake.encrypt_secret", lambda value: f"encrypted:{value}")

    res = client.post(
        "/v1/audits/json",
        json={"repo_url": "https://github.com/example/private-repo", "github_token": "ghp_secret"},
    )

    assert res.status_code == 201
    body = res.json()
    assert "ghp_secret" not in str(body)
    secret = db_session.query(AuditSecret).filter_by(audit_id=UUID(body["id"]), kind="github_token").one()
    assert secret.encrypted_value == "encrypted:ghp_secret"
    assert enqueued == [body["id"]]


def test_create_audit_json_rejects_non_allowlisted_url(client):
    res = client.post("/v1/audits/json", json={"repo_url": "https://example.com/org/repo"})

    assert res.status_code == 400
    assert "allowlist" in res.json()["detail"]


def test_get_audit_returns_404_for_missing_id(client):
    res = client.get(f"/v1/audits/{uuid4()}")

    assert res.status_code == 404


def test_findings_filters_and_detail_route(client, db_session):
    audit = _audit(db_session)
    high = _finding(db_session, audit, severity="High", category="Secret Exposure")
    _finding(db_session, audit, severity="Low", category="Dependency Vulnerability")

    res = client.get(f"/v1/audits/{audit.id}/findings", params={"severity": "High", "tool": "gitleaks"})

    assert res.status_code == 200
    items = res.json()["items"]
    assert [item["id"] for item in items] == [str(high.id)]

    detail = client.get(f"/v1/findings/{high.id}")
    assert detail.status_code == 200
    assert detail.json()["title"] == "High finding"


def test_report_route_prefers_stored_artifact(client, db_session, monkeypatch):
    audit = _audit(db_session)
    _finding(db_session, audit)
    db_session.add(
        Report(
            audit_id=audit.id,
            kind="technical",
            format="json",
            uri=f"s3://bucket/reports/{audit.id}/technical.json",
        )
    )
    db_session.commit()
    monkeypatch.setattr(
        "app.routes.reports.get_report_bytes",
        lambda uri: b'{"audit_id":"stored","summary":{"total_findings":99}}',
    )

    res = client.get(f"/v1/audits/{audit.id}/report", params={"view": "technical", "format": "json"})

    assert res.status_code == 200
    assert res.json()["audit_id"] == "stored"
    assert res.json()["summary"]["total_findings"] == 99


def test_report_route_falls_back_when_stored_artifact_missing(client, db_session, monkeypatch):
    audit = _audit(db_session)
    _finding(db_session, audit)
    db_session.add(
        Report(
            audit_id=audit.id,
            kind="technical",
            format="json",
            uri=f"s3://bucket/reports/{audit.id}/technical.json",
        )
    )
    db_session.commit()
    monkeypatch.setattr(
        "app.routes.reports.get_report_bytes",
        lambda uri: (_ for _ in ()).throw(RuntimeError("object store down")),
    )

    res = client.get(f"/v1/audits/{audit.id}/report", params={"view": "technical", "format": "json"})

    assert res.status_code == 200
    assert res.json()["audit_id"] == str(audit.id)
    assert res.json()["summary"]["total_findings"] == 1


def test_chat_persists_user_and_assistant_turn_when_no_findings(client, db_session):
    audit = _audit(db_session)

    res = client.post(f"/v1/audits/{audit.id}/chat", json={"message": "what should I review first?"})

    assert res.status_code == 200
    body = res.json()
    assert body["session_id"]
    assert len(body["history"]) == 2
    assert body["history"][0]["role"] == "user"
    assert body["history"][1]["role"] == "assistant"
    assert "no findings" in body["history"][1]["content"]
