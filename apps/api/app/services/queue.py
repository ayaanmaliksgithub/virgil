"""Thin Celery client used by API routes to enqueue audits.

The API does NOT import the worker package directly — it sends tasks by name
so the API container does not need scanner code installed.
"""
from __future__ import annotations

from celery import Celery

from app.config import get_settings

_settings = get_settings()
celery_app = Celery("api-client", broker=_settings.redis_url, backend=_settings.redis_url)


def enqueue_audit(audit_id: str) -> None:
    celery_app.send_task("worker.tasks.run_audit", args=[audit_id])
