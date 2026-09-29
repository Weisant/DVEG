"""Minimal JSON chat client based on the OpenAI Python SDK.

This module only communicates with the OpenAI interface. If `base_url` is configured, it can also call an OpenAI-compatible gateway through the official SDK.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

from agent.config import AgentSettings


def _strip_json_fence(text: str) -> str:
    """Remove occasional Markdown code fences returned by the model."""
    stripped = text.strip()
    if stripped.startswith("```json"):
        stripped = stripped[len("```json") :].strip()
    elif stripped.startswith("```"):
        stripped = stripped[len("```") :].strip()

    if stripped.endswith("```"):
        stripped = stripped[:-3].strip()
    return stripped


def _json_error_excerpt(text: str, position: int, radius: int = 700) -> str:
    """Return a compact excerpt around a JSON parse failure."""
    start = max(position - radius, 0)
    end = min(position + radius, len(text))
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}"


def _json_repair_user_prompt(
    *,
    original_user_prompt: str,
    invalid_content: str,
    error: json.JSONDecodeError,
) -> str:
    """Ask the model to regenerate the same answer as syntactically valid JSON."""
    excerpt = _json_error_excerpt(invalid_content, error.pos)
    return (
        f"{original_user_prompt}\n\n"
        "The previous response was not valid JSON and could not be parsed.\n"
        f"Parser error: {error.msg} at line {error.lineno}, column {error.colno}.\n"
        "Invalid response excerpt near the parser error:\n"
        f"{excerpt}\n\n"
        "Regenerate the complete answer as exactly one syntactically valid JSON object. "
        "Escape every quote, backslash, newline, and other control character inside string values. "
        "Do not include Markdown fences or explanatory text."
    )


def _usage_value(usage: Any, key: str) -> int:
    """Read token usage fields from SDK objects or dict-like gateway responses."""
    if isinstance(usage, dict):
        value = usage.get(key, 0)
    else:
        value = getattr(usage, key, 0)
    return int(value or 0)


@dataclass
class JsonChatClient:
    """Request JSON responses through the OpenAI Python SDK."""

    settings: AgentSettings
    _client: OpenAI = field(init=False, repr=False)
    _token_usage: dict[str, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize the underlying OpenAI SDK client from settings."""
        base_url = self.settings.base_url.strip()
        client_kwargs = {
            "api_key": self.settings.api_key,
            "max_retries": 0,
        }
        if base_url:
            client_kwargs["base_url"] = base_url
        self._client = OpenAI(**client_kwargs)
        self._token_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "calls": 0,
        }

    def chat_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        model: str | None = None,
        timeout_seconds: int = 180,
    ) -> dict:
        """Send one JSON chat request and retry minor network or JSON syntax failures."""
        selected_model = model or self.settings.default_model
        current_user_prompt = user_prompt
        last_error: json.JSONDecodeError | None = None
        for parse_attempt in range(3):
            response = self._request_with_retry(
                system_prompt=system_prompt,
                user_prompt=current_user_prompt,
                temperature=temperature if parse_attempt == 0 else 0,
                model=selected_model,
                timeout_seconds=timeout_seconds,
            )
            self._record_token_usage(response)

            content = response.choices[0].message.content
            if not isinstance(content, str):
                raise RuntimeError("Model returned non-text content.")
            stripped_content = _strip_json_fence(content)
            try:
                return json.loads(stripped_content)
            except json.JSONDecodeError as exc:
                last_error = exc
                if parse_attempt >= 2:
                    excerpt = _json_error_excerpt(stripped_content, exc.pos)
                    raise RuntimeError(
                        "Model returned invalid JSON after repair retries: "
                        f"{exc.msg} at line {exc.lineno}, column {exc.colno}.\n"
                        f"Excerpt near error:\n{excerpt}"
                    ) from exc
                current_user_prompt = _json_repair_user_prompt(
                    original_user_prompt=user_prompt,
                    invalid_content=stripped_content,
                    error=exc,
                )

        raise RuntimeError(f"Model returned invalid JSON: {last_error}") from last_error

    def token_usage_snapshot(self) -> dict[str, int]:
        """Return the cumulative token usage observed by this client."""
        return dict(self._token_usage)

    def token_usage_delta(self, before: dict[str, int]) -> dict[str, int]:
        """Return token usage consumed since a previous snapshot."""
        current = self.token_usage_snapshot()
        return {
            key: current.get(key, 0) - before.get(key, 0)
            for key in self._token_usage
        }

    def _record_token_usage(self, response: Any) -> None:
        """Add successful response token usage to the cumulative counter."""
        usage = getattr(response, "usage", None)
        if usage is None:
            self._token_usage["calls"] += 1
            return
        prompt_tokens = _usage_value(usage, "prompt_tokens")
        completion_tokens = _usage_value(usage, "completion_tokens")
        total_tokens = _usage_value(usage, "total_tokens") or (
            prompt_tokens + completion_tokens
        )
        self._token_usage["prompt_tokens"] += prompt_tokens
        self._token_usage["completion_tokens"] += completion_tokens
        self._token_usage["total_tokens"] += total_tokens
        self._token_usage["calls"] += 1

    def _request_with_retry(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        model: str,
        timeout_seconds: int,
        max_retries: int = 2,
    ):
        """Execute the SDK request and perform limited retries for network-layer errors."""
        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return self._client.with_options(
                    timeout=timeout_seconds,
                    max_retries=0,
                ).chat.completions.create(
                    model=model,
                    temperature=temperature,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                )
            except APIStatusError as exc:
                detail = exc.response.text.strip() if exc.response is not None else str(exc)
                if exc.status_code >= 500 and attempt < max_retries:
                    last_error = exc
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise RuntimeError(
                    f"LLM request failed with {exc.status_code} for model {model}: {detail}"
                ) from exc
            except (APIConnectionError, APITimeoutError) as exc:
                last_error = exc
                if attempt >= max_retries:
                    break
                time.sleep(1.5 * (attempt + 1))

        raise RuntimeError(f"LLM request failed: {last_error}") from last_error
