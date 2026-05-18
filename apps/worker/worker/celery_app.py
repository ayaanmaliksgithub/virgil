from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from worker.config import get_settings

_s = get_settings()
celery_app = Celery("virgil", broker=_s.redis_url, backend=_s.redis_url)
celery_app.conf.task_default_queue = "audits"
celery_app.conf.task_acks_late = True
celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.broker_connection_retry_on_startup = True

# Nightly threat-intel refresh: pull EPSS + CISA KEV at 03:17 UTC.
# Off-the-hour so we don't pile up at the same minute as every other cron in
# the world hitting these feeds.
celery_app.conf.beat_schedule = {
    "refresh-threat-intel": {
        "task": "worker.tasks.refresh_threat_intel",
        "schedule": crontab(hour="3", minute="17"),
    },
}

# Discover tasks
import worker.tasks  # noqa: F401, E402
