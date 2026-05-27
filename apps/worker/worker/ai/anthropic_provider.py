from __future__ import annotations

import datetime as _dt
import json
import logging
import threading
import time
from typing import Any, Iterator

import anthropic
import redis as _redis_mod

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


# Daily $ budget. Spend is tracked in Redis (key resets per UTC day) so that
# the cap holds across all worker processes on the same broker. Pricing is
# per-model; an unknown model gets the conservative default. Update the
# table when Anthropic changes pricing.
_MODEL_PRICES_USD_PER_M = {
    "claude-opus-4-7":   (15.0, 75.0),
    "claude-sonnet-4-6": ( 3.0, 15.0),
    "claude-haiku-4-5":  ( 1.0,  5.0),
}
_DEFAULT_PRICES_USD_PER_M = (5.0, 25.0)

_redis_lock = threading.Lock()
_redis_client: _redis_mod.Redis | None = None
# Once we observe over-budget, don't log it on every subsequent call.
_budget_warned_for_day: str | None = None


def _redis() -> _redis_mod.Redis:
    global _redis_client
    if _redis_client is None:
        with _redis_lock:
            if _redis_client is None:
                _redis_client = _redis_mod.from_url(
                    get_settings().redis_url, decode_responses=True,
                )
    return _redis_client


def _today_key() -> str:
    return "virgil:llm:spend:" + _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def _today_spend_usd() -> float:
    try:
        v = _redis().get(_today_key())
        return float(v) if v else 0.0
    except Exception as e:
        log.warning("budget read failed (%s) — allowing call", e)
        return 0.0


def _add_spend_usd(amount: float) -> None:
    if amount <= 0:
        return
    try:
        key = _today_key()
        r = _redis()
        r.incrbyfloat(key, amount)
        # 48h TTL gives us a buffer around the UTC day rollover; the key
        # itself encodes the date so a stale value can never bleed.
        r.expire(key, 48 * 3600)
    except Exception as e:
        log.warning("budget write failed (%s)", e)


def _cost_usd(model: str, in_tokens: int, out_tokens: int) -> float:
    p_in, p_out = _MODEL_PRICES_USD_PER_M.get(model, _DEFAULT_PRICES_USD_PER_M)
    return (in_tokens * p_in + out_tokens * p_out) / 1_000_000.0


def _over_budget() -> bool:
    global _budget_warned_for_day
    cap = get_settings().llm_daily_budget_usd
    if cap <= 0:
        return False  # 0 or negative disables the cap (escape hatch)
    spent = _today_spend_usd()
    if spent < cap:
        return False
    day = _today_key()
    if _budget_warned_for_day != day:
        _budget_warned_for_day = day
        log.warning(
            "daily LLM budget reached: $%.2f spent vs cap $%.2f; "
            "further calls return empty until %s rolls over",
            spent, cap, day,
        )
    return True

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
        if _circuit_open() or _over_budget():
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
        try:
            u = msg.usage
            _add_spend_usd(_cost_usd(self._model, u.input_tokens, u.output_tokens))
        except Exception as e:
            log.warning("usage accounting failed: %s", e)
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
        if _circuit_open() or _over_budget():
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
                try:
                    final = stream.get_final_message()
                    u = final.usage
                    _add_spend_usd(_cost_usd(self._model, u.input_tokens, u.output_tokens))
                except Exception as e:
                    log.warning("usage accounting failed: %s", e)
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
