#!/bin/sh
# API container entrypoint.
#
# Runs alembic migrations, then execs uvicorn. The migration step is
# idempotent — alembic checks the version table — so running every boot
# costs nothing on a populated DB.

set -e

echo "[entrypoint] running alembic migrations…"
alembic upgrade head

echo "[entrypoint] starting uvicorn…"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
