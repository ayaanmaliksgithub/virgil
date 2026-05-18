from __future__ import annotations

import json
from typing import Any, Iterator

import anthropic

from worker.config import get_settings


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
        # Anthropic doesn't have a native JSON-schema mode; we constrain via the
        # prompt and parse the first JSON object out of the response.
        instruction = _schema_instruction(schema)
        msg = self._client.messages.create(
            model=self._model,
            system=system + "\n\n" + instruction,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": user}],
        )
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
        instruction = _schema_instruction(schema)
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
