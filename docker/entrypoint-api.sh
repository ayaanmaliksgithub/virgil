#!/bin/sh
# API container entrypoint.
#
# Runs migrations and (on a fresh DB) seeds the demo NodeGoat audit, then
# execs uvicorn. Idempotent — migrations are alembic-managed, and the seed
# checks for its sentinel UUID before inserting.
#
# Disable the demo seed with `SEED_DEMO_AUDIT=false` in the environment.

set -e

echo "[entrypoint] running alembic migrations…"
alembic upgrade head

if [ "${SEED_DEMO_AUDIT:-true}" != "false" ]; then
  echo "[entrypoint] checking demo seed…"
  python -m app.seed || echo "[entrypoint] seed step exited non-zero; continuing"
else
  echo "[entrypoint] SEED_DEMO_AUDIT=false — skipping demo seed"
fi

echo "[entrypoint] starting uvicorn…"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
