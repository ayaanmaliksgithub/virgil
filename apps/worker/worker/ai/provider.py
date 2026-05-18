"""LLM provider abstraction.

`get_provider()` selects Anthropic or OpenAI based on settings. Both providers
must support a JSON-schema-constrained completion so the worker can refuse
free-form output that drifts off-schema.
"""
from __future__ import annotations

from typing import Any, Protocol

from worker.config import get_settings


class LLMProvider(Protocol):
    name: str

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> dict[str, Any]: ...


class _NullProvider:
    """Used when no API key is configured. Returns empty objects so the audit
    pipeline degrades gracefully without an LLM."""
    name = "null"

    def complete_json(self, *, system, user, schema, max_tokens=2048, temperature=0.2):  # noqa: D401
        return {}


def get_provider() -> LLMProvider:
    settings = get_settings()
    name = (settings.llm_provider or "").lower()
    if name == "anthropic" and settings.anthropic_api_key:
        from worker.ai.anthropic_provider import AnthropicProvider
        return AnthropicProvider()
    if name == "openai" and settings.openai_api_key:
        from worker.ai.openai_provider import OpenAIProvider
        return OpenAIProvider()
    return _NullProvider()
