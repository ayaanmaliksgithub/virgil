from __future__ import annotations

import json
from typing import Any, Iterator

from openai import OpenAI

from worker.config import get_settings


class OpenAIProvider:
    name = "openai"

    def __init__(self) -> None:
        s = get_settings()
        self._client = OpenAI(api_key=s.openai_api_key)
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
        resp = self._client.chat.completions.create(
            model=self._model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=_messages(system, user, schema),
        )
        content = resp.choices[0].message.content or "{}"
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}

    def stream_json(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> Iterator[str]:
        """Yield raw text deltas from a streaming chat completion.

        Like the Anthropic provider, the deltas are still JSON-shaped;
        chat.answer_stream is responsible for extracting the `answer` field.
        """
        stream = self._client.chat.completions.create(
            model=self._model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=_messages(system, user, schema),
            stream=True,
        )
        for event in stream:
            choices = getattr(event, "choices", None) or []
            if not choices:
                continue
            delta = getattr(choices[0], "delta", None)
            if delta is None:
                continue
            chunk = getattr(delta, "content", None)
            if chunk:
                yield chunk


def _messages(system: str, user: str, schema: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system + "\n\nRespond as a single JSON object."},
        {"role": "user", "content": user + f"\n\nSchema:\n{json.dumps(schema)}"},
    ]
