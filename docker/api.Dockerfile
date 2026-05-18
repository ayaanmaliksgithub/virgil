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

WORKDIR /srv/apps/api
RUN uv pip install --system --no-cache .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
