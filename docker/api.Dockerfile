FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# WeasyPrint runtime deps. Without these the PDF route returns 503 — the
# Python package itself imports fine but rendering fails when libcairo isn't
# present. fonts-dejavu provides the monospace face referenced in the PDF CSS.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libcairo2 \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libgdk-pixbuf-2.0-0 \
      libffi-dev \
      shared-mime-info \
      fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

RUN pip install --no-cache-dir "uv>=0.4"

COPY packages/audit_core /srv/packages/audit_core
COPY apps/api /srv/apps/api
# Worker package needed by the chat route (worker.ai.chat) and shared utilities.
# The api container does not run celery — it only imports for in-process LLM calls.
COPY apps/worker /srv/apps/worker

WORKDIR /srv/apps/api
RUN uv pip install --system --no-cache .
# Install worker package + its LLM SDK deps so api can import worker.ai.chat
RUN uv pip install --system --no-cache /srv/apps/worker


# Entrypoint runs alembic + the demo-audit seed before launching uvicorn,
# so a fresh `docker compose up` lands on a populated UI with no manual
# `alembic upgrade head` step. The seed is idempotent and disable-able via
# `SEED_DEMO_AUDIT=false`.
COPY docker/entrypoint-api.sh /usr/local/bin/entrypoint-api.sh
RUN chmod +x /usr/local/bin/entrypoint-api.sh

EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/entrypoint-api.sh"]
