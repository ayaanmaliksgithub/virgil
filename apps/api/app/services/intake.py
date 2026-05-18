"""Audit intake — URL validation and ZIP upload handling.

Creates an audits row + enqueues the worker task. Does NOT clone or extract
itself; that work belongs to the sandboxed worker.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.models import Audit, AuditSecret
from app.security.secrets import SecretConfigError, encrypt_secret
from app.security.url_validator import InvalidRepoURL, validate_repo_url

log = logging.getLogger(__name__)


class IntakeError(ValueError):
    pass


def create_audit_from_url(
    db: Session,
    repo_url: str,
    *,
    github_token: str | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> Audit:
    try:
        clean = validate_repo_url(repo_url)
    except InvalidRepoURL as e:
        raise IntakeError(str(e)) from e

    token = (github_token or "").strip()
    if token and not clean.startswith("https://github.com/"):
        raise IntakeError("GitHub private repository tokens are only accepted for github.com URLs")

    # §17 #5 — both PR-mode SHAs must be set together or neither.
    if (base_sha is None) != (head_sha is None):
        raise IntakeError("base_sha and head_sha must be provided together for PR-mode")

    audit = Audit(
        source_kind="url",
        source_ref=clean,
        state="pending",
        phase="queued",
        base_sha=base_sha,
        head_sha=head_sha,
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)
    if token:
        try:
            encrypted = encrypt_secret(token)
        except SecretConfigError as e:
            db.delete(audit)
            db.commit()
            raise IntakeError(str(e)) from e
        db.add(AuditSecret(audit_id=audit.id, kind="github_token", encrypted_value=encrypted))
        db.commit()
    return audit


async def create_audit_from_zip(db: Session, upload: UploadFile, staging_dir: Path) -> Audit:
    settings = get_settings()
    if not upload.filename or not upload.filename.lower().endswith(".zip"):
        raise IntakeError("Upload must be a .zip archive")

    staging_dir.mkdir(parents=True, exist_ok=True)

    audit = Audit(source_kind="zip", source_ref=upload.filename, state="pending", phase="queued")
    db.add(audit)
    db.commit()
    db.refresh(audit)

    dest = staging_dir / f"{audit.id}.zip"
    written = 0
    with dest.open("wb") as f:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > settings.max_upload_bytes:
                f.close()
                dest.unlink(missing_ok=True)
                db.delete(audit)
                db.commit()
                raise IntakeError("Upload exceeds maximum size")
            f.write(chunk)

    audit.source_ref = str(dest)
    db.commit()
    db.refresh(audit)
    return audit
