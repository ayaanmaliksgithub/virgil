from __future__ import annotations

import os
import time
import zipfile
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_COMPOSE_SMOKE") != "1",
    reason="set RUN_COMPOSE_SMOKE=1 with the compose stack running to execute the smoke test",
)


API_BASE = os.environ.get("API_BASE", "http://localhost:8000").rstrip("/")
TIMEOUT_SECONDS = int(os.environ.get("COMPOSE_SMOKE_TIMEOUT_SECONDS", "600"))


def _fixture_zip(tmp_path: Path) -> Path:
    repo = tmp_path / "fixture-repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        '{"name":"audit-smoke","version":"1.0.0","dependencies":{"lodash":"4.17.11"}}\n',
        encoding="utf-8",
    )
    (repo / "config.py").write_text(
        "\n".join(
            [
                'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
                'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "audit-smoke.zip"
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in repo.rglob("*"):
            zf.write(path, path.relative_to(repo))
    return out


def test_compose_zip_audit_smoke(tmp_path):
    archive = _fixture_zip(tmp_path)
    with httpx.Client(base_url=API_BASE, timeout=30.0) as client:
        with archive.open("rb") as f:
            create = client.post("/v1/audits", files={"file": ("audit-smoke.zip", f, "application/zip")})
        assert create.status_code == 201, create.text
        audit_id = create.json()["id"]

        deadline = time.monotonic() + TIMEOUT_SECONDS
        audit = create.json()
        while time.monotonic() < deadline:
            audit_res = client.get(f"/v1/audits/{audit_id}")
            assert audit_res.status_code == 200, audit_res.text
            audit = audit_res.json()
            if audit["state"] in ("succeeded", "failed"):
                break
            time.sleep(3)

        assert audit["state"] == "succeeded", audit

        findings = client.get(f"/v1/audits/{audit_id}/findings")
        assert findings.status_code == 200, findings.text
        items = findings.json()["items"]
        assert items, "expected at least one finding from the fixture ZIP"

        report = client.get(
            f"/v1/audits/{audit_id}/report",
            params={"view": "technical", "format": "json"},
        )
        assert report.status_code == 200, report.text
        report_body = report.json()
        assert report_body["audit_id"] == audit_id
        assert report_body["summary"]["total_findings"] == len(items)
