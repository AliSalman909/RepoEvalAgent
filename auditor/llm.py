"""LLM client: a thin wrapper over Google's official Gen AI SDK (Gemini).

Only plain ``models.generate_content`` calls are used, with the SDK's automatic
function calling switched OFF: the agent loop, tool dispatch and control flow
live in ``auditor/loop.py`` (no agent framework).

The loop speaks a small provider-neutral transcript format:

    {"role": "user", "content": "text"}
    {"role": "assistant", "raw": <the model's own Content, passed back unchanged>}
    {"role": "tool", "results": [{"id", "name", "content", "is_error"}], "note": "text or None"}

This module converts it to Gemini ``Content`` objects. Model turns are re-sent
exactly as received, which keeps Gemini's thought signatures intact.
"""

from __future__ import annotations

import math
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

# The model can be overridden with GEMINI_MODEL or the --model CLI flag.
DEFAULT_MODEL = "gemini-flash-lite-latest"
DEFAULT_REQUESTS_PER_MINUTE = 10.0
DEFAULT_MAX_OUTPUT_TOKENS = 16384

# Gemini finish reasons, normalised for the loop.
_REFUSAL_REASONS = {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "IMAGE_SAFETY"}
_MALFORMED_REASONS = {"MALFORMED_FUNCTION_CALL", "UNEXPECTED_TOOL_CALL", "TOO_MANY_TOOL_CALLS"}


class LLMError(Exception):
    """The LLM call failed in a way the run cannot recover from."""


class LLMConfigError(LLMError):
    """Missing/invalid credentials or model configuration."""


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    """Provider-neutral view of one model turn.

    stop_reason is one of: "tool_use", "end_turn", "max_tokens", "refusal", "malformed_tool_call".
    ``raw_content`` is stored in the transcript and handed back to the provider unchanged.
    """

    raw_content: Any
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str | None
    usage: dict[str, int] = field(default_factory=dict)


class LLMClient(Protocol):
    model: str

    def complete(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse: ...


def _api_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


class GeminiClient:
    def __init__(
        self,
        model: str | None = None,
        thinking_level: str | None = None,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        timeout_s: float = 300.0,
        retry_attempts: int = 5,
        requests_per_minute: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        try:
            from google import genai
            from google.genai import errors, types
        except ImportError as exc:  # pragma: no cover - dependency is in requirements.txt
            raise LLMConfigError("the 'google-genai' package is not installed; run: pip install -r requirements.txt") from exc
        self._types, self._errors = types, errors

        key = _api_key()
        if not key:
            raise LLMConfigError("no Gemini API key found (GEMINI_API_KEY is not set)")
        self.model = (model or os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL).strip()
        if not self.model:
            self.model = DEFAULT_MODEL
        raw_rpm = requests_per_minute
        if raw_rpm is None:
            raw_rpm = os.environ.get("GEMINI_REQUESTS_PER_MINUTE", str(DEFAULT_REQUESTS_PER_MINUTE))
        try:
            self.requests_per_minute = float(raw_rpm)
        except (TypeError, ValueError):
            raise LLMConfigError("GEMINI_REQUESTS_PER_MINUTE must be a number greater than zero") from None
        if not math.isfinite(self.requests_per_minute) or self.requests_per_minute <= 0:
            raise LLMConfigError("GEMINI_REQUESTS_PER_MINUTE must be greater than zero")
        self._request_interval_s = 60.0 / self.requests_per_minute
        self._clock = clock
        self._sleep = sleep
        self._last_request_at: float | None = None
        # Thinking level is model-specific (some models reject some levels), so it is only sent when configured.
        level = thinking_level if thinking_level is not None else os.environ.get("GEMINI_THINKING_LEVEL", "")
        self.thinking_level = level.strip().lower() or None
        self.max_output_tokens = max_output_tokens
        http_options = types.HttpOptions(
            timeout=int(timeout_s * 1000),  # milliseconds
            retry_options=types.HttpRetryOptions(
                attempts=retry_attempts, initial_delay=2.0, max_delay=60.0,
                http_status_codes=[408, 429, 500, 502, 503, 504],
            ),
        )
        try:
            self._client = genai.Client(api_key=key, http_options=http_options)
        except Exception as exc:
            raise LLMConfigError(f"could not create Gemini client: {exc}") from exc

    # ---------------------------------------------------------------- conversion

    def _tools(self, tools: list[dict[str, Any]]) -> list[Any]:
        t = self._types
        decls = [
            t.FunctionDeclaration(name=s["name"], description=s["description"],
                                  parameters_json_schema=s["input_schema"])
            for s in tools
        ]
        return [t.Tool(function_declarations=decls)] if decls else []

    def to_contents(self, messages: list[dict[str, Any]]) -> list[Any]:
        """Neutral transcript -> list[types.Content]."""
        t = self._types
        contents = []
        for m in messages:
            role = m["role"]
            if role == "user":
                contents.append(t.Content(role="user", parts=[t.Part(text=m["content"])]))
            elif role == "assistant":
                contents.append(m["raw"])  # unchanged: preserves thought signatures
            elif role == "tool":
                parts = []
                for r in m["results"]:
                    payload = {"error": r["content"]} if r.get("is_error") else {"output": r["content"]}
                    parts.append(t.Part(function_response=t.FunctionResponse(id=r.get("id"), name=r["name"], response=payload)))
                if m.get("note"):
                    parts.append(t.Part(text=m["note"]))
                contents.append(t.Content(role="user", parts=parts))
            else:
                raise ValueError(f"unknown transcript role {role!r}")
        return contents

    def parse_response(self, resp: Any) -> LLMResponse:
        """types.GenerateContentResponse -> LLMResponse."""
        usage: dict[str, int] = {}
        um = getattr(resp, "usage_metadata", None)
        if um is not None:
            for ours, theirs in (("input_tokens", "prompt_token_count"), ("output_tokens", "candidates_token_count"),
                                 ("cache_read_input_tokens", "cached_content_token_count"),
                                 ("thinking_tokens", "thoughts_token_count")):
                usage[ours] = getattr(um, theirs, None) or 0

        feedback = getattr(resp, "prompt_feedback", None)
        if not resp.candidates:  # the prompt itself was blocked (prompt_feedback.block_reason)
            reason = getattr(getattr(feedback, "block_reason", None), "name", None) or "no candidates returned"
            return LLMResponse(raw_content=None, text=f"(blocked: {reason})", tool_calls=[],
                               stop_reason="refusal", usage=usage)

        cand = resp.candidates[0]
        finish = getattr(cand.finish_reason, "name", None) or str(cand.finish_reason or "")
        content = cand.content
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for part in (content.parts if content and content.parts else []):
            if part.function_call is not None:
                fc = part.function_call
                calls.append(ToolCall(id=fc.id or f"call_{uuid.uuid4().hex[:12]}", name=fc.name or "",
                                      input=dict(fc.args or {})))
            elif part.text and not part.thought:
                text_parts.append(part.text)

        if finish in _REFUSAL_REASONS:
            stop = "refusal"
        elif finish in _MALFORMED_REASONS:
            stop = "malformed_tool_call"
        elif finish == "MAX_TOKENS":
            stop = "max_tokens"
        elif calls:
            stop = "tool_use"
        else:
            stop = "end_turn"
        if content is None or not content.parts:
            # Keep the transcript well-formed even when the model returned nothing.
            content = self._types.Content(role="model", parts=[self._types.Part(text="(no content)")])
        return LLMResponse(raw_content=content, text="\n".join(text_parts).strip(), tool_calls=calls,
                           stop_reason=stop, usage=usage)

    # -------------------------------------------------------------------- call

    def _wait_for_request_slot(self) -> None:
        """Evenly space top-level API calls so the configured RPM is never exceeded by this client."""
        now = self._clock()
        if self._last_request_at is not None:
            wait_s = self._request_interval_s - (now - self._last_request_at)
            if wait_s > 0:
                self._sleep(wait_s)
                now = self._clock()
        self._last_request_at = now

    def complete(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        t, errors = self._types, self._errors
        config = t.GenerateContentConfig(
            system_instruction=system,
            tools=self._tools(tools),
            # We run the loop ourselves: never let the SDK call Python functions on its own.
            automatic_function_calling=t.AutomaticFunctionCallingConfig(disable=True),
            max_output_tokens=self.max_output_tokens,
            thinking_config=t.ThinkingConfig(thinking_level=self.thinking_level) if self.thinking_level else None,
        )
        try:
            self._wait_for_request_slot()
            resp = self._client.models.generate_content(
                model=self.model, contents=self.to_contents(messages), config=config,
            )
        except errors.APIError as exc:
            raise _map_api_error(exc, self.model) from exc
        except Exception as exc:
            raise _map_transport_error(exc) from exc
        return self.parse_response(resp)


def _map_api_error(exc: Any, model: str) -> LLMError:
    code = getattr(exc, "code", None)
    message = (getattr(exc, "message", None) or str(exc))[:400].rstrip(" .")
    low = message.lower()
    if code in (401, 403) or "api key not valid" in low or "api_key_invalid" in low or "permission denied" in low:
        return LLMConfigError(f"Gemini API rejected the credentials: {message}")
    if code == 404:
        return LLMConfigError(f"model '{model}' not found or not available to this key: {message}")
    if code == 429:
        return LLMError(f"rate limited / quota exhausted on the Gemini API after retries: {message}")
    if code == 400:
        return LLMError(f"Gemini API rejected the request: {message}")
    return LLMError(f"Gemini API error {code}: {message}")


def _map_transport_error(exc: Exception) -> LLMError:
    name = type(exc).__name__.lower()
    if "timeout" in name:
        return LLMError("Gemini API request timed out after retries")
    if any(k in name for k in ("connect", "network", "transport", "remoteprotocol")):
        return LLMError(f"could not reach the Gemini API: {exc}")
    return LLMError(f"Gemini request failed: {type(exc).__name__}: {exc}")
