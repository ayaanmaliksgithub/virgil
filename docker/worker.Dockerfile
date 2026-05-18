FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# The worker shells out to docker/podman to launch sandbox containers.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-26.1.4.tgz \
      | tar -xz -C /usr/local/bin --strip-components=1 docker/docker \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "uv>=0.4"

WORKDIR /srv
COPY packages/audit_core /srv/packages/audit_core
COPY apps/api /srv/apps/api
COPY apps/worker /srv/apps/worker

WORKDIR /srv/apps/worker
RUN uv pip install --system --no-cache .

CMD ["celery", "-A", "worker.celery_app:celery_app", "worker", "--loglevel=info", "-Q", "audits", "--concurrency=2"]
