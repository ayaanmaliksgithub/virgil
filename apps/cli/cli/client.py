"""HTTP client for the audit API.

Thin wrapper over `requests`. Centralizes the base URL + error handling so
the command modules stay readable. Does NOT carry retry logic — a CLI
session is interactive, and silent retries on top of `requests` calls
hide signal a user wants to see (network down, server hung).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator

import requests

from cli import config


HTTP_TIMEOUT = 30
CHAT_TIMEOUT = 120  # LLM round-trips can sit well past the default.


class ApiError(RuntimeError):
    def __init__(self, status: int, detail: str = ""):
        super().__init__(f"API {status}: {detail}".rstrip(": "))
        self.status = status
        self.detail = detail


class ApiUnreachable(RuntimeError):
    """Network failure — distinct from a 5xx so the CLI can suggest
    `docker compose up` vs. "check API logs"."""


def _base_url() -> str:
    return config.api_url().rstrip("/")


def _request(method: str, path: str, **kwargs) -> requests.Response:
    url = _base_url() + path
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    try:
        res = requests.request(method, url, **kwargs)
    except requests.exceptions.ConnectionError as e:
        raise ApiUnreachable(str(e)) from e
    except requests.exceptions.Timeout as e:
        raise ApiUnreachable(f"timeout after {HTTP_TIMEOUT}s") from e
    if not res.ok:
        raise ApiError(res.status_code, res.text[:500])
    return res


def submit_zip(zip_path: Path) -> dict:
    with zip_path.open("rb") as f:
        files = {"file": (zip_path.name, f, "application/zip")}
        res = _request("POST", "/v1/audits", files=files)
    return res.json()


def submit_url(repo_url: str, *, base_sha: str | None = None, head_sha: str | None = None) -> dict:
    body: dict = {"repo_url": repo_url}
    if base_sha and head_sha:
        body["base_sha"] = base_sha
        body["head_sha"] = head_sha
    res = _request("POST", "/v1/audits/json", json=body)
    return res.json()


def get_audit(audit_id: str) -> dict:
    return _request("GET", f"/v1/audits/{audit_id}").json()


def list_findings(audit_id: str, *, include_suppressed: bool = False) -> list[dict]:
    params = {}
    if include_suppressed:
        params["include_suppressed"] = "true"
    return _request("GET", f"/v1/audits/{audit_id}/findings", params=params).json()["items"]


def get_clusters(audit_id: str, *, include_unreachable: bool = False) -> dict:
    params = {"include_unreachable": "true"} if include_unreachable else {}
    return _request("GET", f"/v1/audits/{audit_id}/findings/clusters", params=params).json()


def get_finding(finding_id: str) -> dict:
    return _request("GET", f"/v1/findings/{finding_id}").json()


def get_suggested_questions(audit_id: str) -> list[str]:
    return _request("GET", f"/v1/audits/{audit_id}/chat/suggested").json().get("items", [])


def post_chat(audit_id: str, message: str, *, session_id: str | None = None) -> dict:
    body: dict = {"message": message}
    if session_id:
        body["session_id"] = session_id
    res = _request("POST", f"/v1/audits/{audit_id}/chat", json=body, timeout=CHAT_TIMEOUT)
    return res.json()


def post_chat_stream(audit_id: str, message: str, *, session_id: str | None = None) -> Iterator[dict]:
    """Stream chat tokens as SSE.

    Yields decoded events: `{"event": "session"|"token"|"done"|"error", "data": ...}`
    where `data` is the already-JSON-decoded payload from the SSE frame.

    On `done` the caller should replace whatever tokens were rendered with the
    final `message.content`: the safety validator runs at end-of-stream and
    may refuse — in which case the visible tokens are stale.
    """
    body: dict = {"message": message}
    if session_id:
        body["session_id"] = session_id
    url = _base_url() + f"/v1/audits/{audit_id}/chat/stream"
    try:
        with requests.post(url, json=body, stream=True, timeout=CHAT_TIMEOUT) as res:
            if not res.ok:
                raise ApiError(res.status_code, res.text[:500])
            event = "message"
            data_lines: list[str] = []
            for raw in res.iter_lines(decode_unicode=True):
                if raw is None:
                    continue
                if raw == "":
                    if data_lines:
                        import json as _json
                        joined = "\n".join(data_lines)
                        try:
                            payload = _json.loads(joined)
                        except _json.JSONDecodeError:
                            payload = {"raw": joined}
                        yield {"event": event, "data": payload}
                    event, data_lines = "message", []
                    continue
                if raw.startswith(":"):
                    continue
                if raw.startswith("event:"):
                    event = raw[6:].strip()
                elif raw.startswith("data:"):
                    data_lines.append(raw[5:].lstrip(" "))
    except requests.exceptions.ConnectionError as e:
        raise ApiUnreachable(str(e)) from e


def get_chat_session(audit_id: str, session_id: str) -> dict:
    return _request("GET", f"/v1/audits/{audit_id}/chat/{session_id}").json()


def get_report(audit_id: str, *, view: str = "technical", format: str = "json") -> bytes:
    res = _request(
        "GET",
        f"/v1/audits/{audit_id}/report",
        params={"view": view, "format": format},
    )
    return res.content


def stream_events(audit_id: str) -> Iterator[dict]:
    """Yield decoded SSE event dicts until the stream ends.

    Each event looks like `{"event": "log"|"done", "phase": str, "message": str}`.
    """
    url = _base_url() + f"/v1/audits/{audit_id}/events"
    try:
        with requests.get(url, stream=True, timeout=None) as res:
            if not res.ok:
                raise ApiError(res.status_code, res.text[:500])
            event = "message"
            data_lines: list[str] = []
            for raw in res.iter_lines(decode_unicode=True):
                if raw is None:
                    continue
                if raw == "":
                    if data_lines:
                        yield {"event": event, "data": "\n".join(data_lines)}
                    event, data_lines = "message", []
                    continue
                if raw.startswith(":"):
                    continue
                if raw.startswith("event:"):
                    event = raw[6:].strip()
                elif raw.startswith("data:"):
                    data_lines.append(raw[5:].lstrip(" "))
    except requests.exceptions.ConnectionError as e:
        raise ApiUnreachable(str(e)) from e


def poll_until_terminal(audit_id: str, *, interval: float = 1.5, max_seconds: float = 1800) -> dict:
    """Polling fallback when SSE is unavailable. Returns the final audit dict."""
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        audit = get_audit(audit_id)
        if audit["state"] in ("succeeded", "failed"):
            return audit
        time.sleep(interval)
    raise TimeoutError(f"audit {audit_id} did not finish within {max_seconds}s")
