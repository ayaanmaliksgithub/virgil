"""HTTP client for the audit API.

Thin wrapper over `requests`. Centralizes the base URL + error handling so
the command modules stay readable. Does NOT carry retry logic — a CLI
session is interactive, and silent retries on top of `requests` calls
hide signal a user wants to see (network down, server hung).

One exception: if the saved api_url points at localhost and that's
unreachable, we fall back to the hosted default once per process and
warn on stderr. Keeps `pipx install virgilhq && virgil scan` working
for users with stale dev configs without clobbering their saved URL.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

import requests

from cli import config


HTTP_TIMEOUT = 30
CHAT_TIMEOUT = 120  # LLM round-trips can sit well past the default.

_LOCALISH_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_runtime_base_override: str | None = None


class ApiError(RuntimeError):
    def __init__(self, status: int, detail: str = ""):
        super().__init__(f"API {status}: {detail}".rstrip(": "))
        self.status = status
        self.detail = detail


class ApiUnreachable(RuntimeError):
    """Network failure — distinct from a 5xx so the CLI can suggest
    `docker compose up` vs. "check API logs"."""


def _is_localish(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in _LOCALISH_HOSTS or host.endswith(".local") or host.endswith(".lan")


def _maybe_fall_back_to_hosted() -> bool:
    """Switch this process to the hosted default if the saved api_url is a
    stale localhost. One-shot: never fires twice in the same process."""
    global _runtime_base_override
    if _runtime_base_override is not None:
        return False
    current = config.api_url()
    if not _is_localish(current):
        return False
    if current.rstrip("/") == config.DEFAULT_API_URL.rstrip("/"):
        return False
    _runtime_base_override = config.DEFAULT_API_URL
    print(
        f"note: saved api_url {current} unreachable — using hosted default "
        f"{config.DEFAULT_API_URL} for this run "
        f"(run `virgil config unset api_url` to make it permanent)",
        file=sys.stderr,
    )
    return True


def _base_url() -> str:
    if _runtime_base_override is not None:
        return _runtime_base_override.rstrip("/")
    return config.api_url().rstrip("/")


def _request(method: str, path: str, **kwargs) -> requests.Response:
    url = _base_url() + path
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    try:
        res = requests.request(method, url, **kwargs)
    except requests.exceptions.ConnectionError as e:
        if _maybe_fall_back_to_hosted():
            return _request(method, path, **kwargs)
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
    try:
        res_ctx = requests.post(
            _base_url() + f"/v1/audits/{audit_id}/chat/stream",
            json=body, stream=True, timeout=CHAT_TIMEOUT,
        )
    except requests.exceptions.ConnectionError as e:
        if _maybe_fall_back_to_hosted():
            yield from post_chat_stream(audit_id, message, session_id=session_id)
            return
        raise ApiUnreachable(str(e)) from e
    with res_ctx as res:
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

    Each yielded item is `{"event": "phase"|"log"|"done", "data": dict}` where
    `data` is the JSON-decoded payload from the SSE frame. Typical shapes:
      phase: {"phase": str, "state": str}
      log:   {"ts": str, "phase": str, "level": str, "message": str}
      done:  {} or terminal state info
    """
    try:
        res_ctx = requests.get(
            _base_url() + f"/v1/audits/{audit_id}/events",
            stream=True, timeout=None,
        )
    except requests.exceptions.ConnectionError as e:
        if _maybe_fall_back_to_hosted():
            yield from stream_events(audit_id)
            return
        raise ApiUnreachable(str(e)) from e
    with res_ctx as res:
        if not res.ok:
            raise ApiError(res.status_code, res.text[:500])
        event = "message"
        data_lines: list[str] = []
        # chunk_size=1 forces per-byte yielding from the underlying socket so
        # SSE events surface in real time. Default chunk_size buffers up to
        # ~512 bytes; for SSE that means the spinner can sit on a stale phase
        # for tens of seconds while the next event waits in the buffer.
        for raw in res.iter_lines(decode_unicode=True, chunk_size=1):
            if raw is None:
                continue
            if raw == "":
                if data_lines:
                    joined = "\n".join(data_lines)
                    try:
                        payload = json.loads(joined)
                    except json.JSONDecodeError:
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


def poll_until_terminal(audit_id: str, *, interval: float = 1.5, max_seconds: float = 1800) -> dict:
    """Polling fallback when SSE is unavailable. Returns the final audit dict."""
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        audit = get_audit(audit_id)
        if audit["state"] in ("succeeded", "failed"):
            return audit
        time.sleep(interval)
    raise TimeoutError(f"audit {audit_id} did not finish within {max_seconds}s")
