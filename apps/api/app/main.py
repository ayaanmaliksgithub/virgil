from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routes import audits, chat, events, findings, lifecycle, reports

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s :: %(message)s")

settings = get_settings()
app = FastAPI(title="Virgil", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(audits.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(events.router)
app.include_router(chat.router)
app.include_router(lifecycle.router)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}
