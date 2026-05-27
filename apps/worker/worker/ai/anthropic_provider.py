from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Iterator

import anthropic

from worker.config import get_settings


log = logging.getLogger(__name__)


# Process-wide circuit breaker. When an Anthropic call returns one of the
# terminal errors below, we stop calling the API for a short cooldown so the
# rest of an in-flight audit doesn't burn 93 identical 400s in a row. The
# state is module-level (not per-instance) because get_provider() returns a
# fresh AnthropicProvider per call site; we need the flag to outlive a single
# instance. Callers already treat both exceptions and empty dicts as "no LLM
# output", so the short-circuit degrades cleanly to scanner-only audits.
_circuit_lock = threading.Lock()
_circuit_open_until: float = 0.0  # epoch seconds; 0 means closed (healthy)

# Substrings in the human-readable error message that indicate a 400 is
# unrecoverable in the short term (typically: drained credit balance). The
# Anthropic API doesn't include a machine-readable error code for this case
# — just a prose message — so we match on the stable English phrase.
_BAD_REQUEST_TERMINAL_PHRASES = (
    "credit balance is too low",
    "credit_balance_too_low",  # belt-and-braces in case the SDK ever surfaces the code
)
_CIRCUIT_COOLDOWN_SEC = 60.0


def _circuit_open() -> bool:
    return _circuit_open_until > time.monotonic()


def _trip_circuit(reason: str) -> None:
    global _circuit_open_until
    with _circuit_lock:
        _circuit_open_until = time.monotonic() + _CIRCUIT_COOLDOWN_SEC
    log.warning(
        "anthropic provider: tripping circuit breaker for %.0fs (%s)",
        _CIRCUIT_COOLDOWN_SEC, reason,
    )


def _is_terminal_error(exc: BaseException) -> bool:
    # 401 (auth), 403 (permission), 429 (rate-limit) are unrecoverable within
    # the cooldown window — give it a minute before trying again.
    if isinstance(exc, (
        anthropic.AuthenticationError,
        anthropic.PermissionDeniedError,
        anthropic.RateLimitError,
    )):
        return True
    # 400 (bad request) covers many things; only trip on drained-credit, not
    # on caller bugs (malformed request, prompt too long, etc.).
    if isinstance(exc, anthropic.BadRequestError):
        msg = str(getattr(exc, "message", "") or exc).lower()
        return any(p in msg for p in _BAD_REQUEST_TERMINAL_PHRASES)
    return False


class AnthropicProvider:
    name = "anthropic"

    def __init__(self) -> None:
        s = get_settings()
        self._client = anthropic.Anthropic(api_key=s.anthropic_api_key)
        self._model = s.llm_model

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        if _circuit_open():
            return {}
        # Anthropic doesn't have a native JSON-schema mode; we constrain via the
        # prompt and parse the first JSON object out of the response.
        instruction = _schema_instruction(schema)
        try:
            msg = self._client.messages.create(
                model=self._model,
                system=system + "\n\n" + instruction,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as e:
            if _is_terminal_error(e):
                _trip_circuit(str(e)[:160])
            raise
        text = "".join(block.text for block in msg.content if getattr(block, "type", "") == "text")
        return _extract_json(text) or {}

    def stream_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> Iterator[str]:
        """Yield raw text deltas as they arrive from the model.

        The output is still JSON-shaped — callers (chat.answer_stream) are
        responsible for incrementally extracting the `answer` field. We
        intentionally do not parse here so the provider stays a pure transport.
        """
        if _circuit_open():
            return
        instruction = _schema_instruction(schema)
        try:
            with self._client.messages.stream(
                model=self._model,
                system=system + "\n\n" + instruction,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": user}],
            ) as stream:
                for delta in stream.text_stream:
                    if delta:
                        yield delta
        except Exception as e:
            if _is_terminal_error(e):
                _trip_circuit(str(e)[:160])
            raise


def _schema_instruction(schema: dict[str, Any]) -> str:
    return (
        "Respond with a single JSON object that strictly matches this schema. "
        "Do NOT include prose outside the JSON object.\n\n"
        f"Schema:\n{json.dumps(schema)}"
    )


def _extract_json(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
