"""Minimal OpenAI-compatible chat completions client (stdlib only).

Tracks per-model token usage, cached-input tokens, wall time and request count so
the agent can report the exact schema required by CyberGym's SUBMISSION.md.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from typing import Any, Iterable


@dataclass
class ModelUsage:
    """Per-model usage, averaged over tasks at report time."""

    input_tokens: int = 0          # non-cached input
    cache_read_tokens: int = 0     # prompt-cache hits
    cache_creation_tokens: int = 0  # prompt-cache writes (approx)
    output_tokens: int = 0
    llm_requests: int = 0
    time_cost_sec: float = 0.0

    def add(self, other: "ModelUsage") -> None:
        self.input_tokens += other.input_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_creation_tokens += other.cache_creation_tokens
        self.output_tokens += other.output_tokens
        self.llm_requests += other.llm_requests
        self.time_cost_sec += other.time_cost_sec

    def as_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "output_tokens": self.output_tokens,
            "llm_requests": self.llm_requests,
            "time_cost_sec": round(self.time_cost_sec, 1),
        }


@dataclass
class UsageLedger:
    usage: dict[str, ModelUsage] = field(default_factory=dict)

    def record(self, model: str, usage: ModelUsage) -> None:
        if model not in self.usage:
            self.usage[model] = ModelUsage()
        self.usage[model].add(usage)


class LLMError(RuntimeError):
    pass


class LLMClient:
    """Thin wrapper around /chat/completions with JSON-object support."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        ledger: UsageLedger | None = None,
        timeout: float = 180.0,
        max_retries: int = 3,
        api_key_fallback: str = "",
    ):
        if base_url.endswith("/"):
            base_url = base_url[:-1]
        if not base_url.endswith("/chat/completions"):
            # A bare host has no path, but gateways and most providers serve
            # the OpenAI-compatible surface under /v1. An explicit path (e.g.
            # ".../v1" or a self-hosted "/api/openai") is used as given.
            if not urlsplit(base_url).path:
                base_url += "/v1"
            base_url += "/chat/completions"
        self.endpoint = base_url
        self.api_key = api_key
        self._api_key_fallback = api_key_fallback
        self.model = model
        self.ledger = ledger or UsageLedger()
        self.timeout = timeout
        self.max_retries = max_retries

    def _request(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int,
        temperature: float,
        json_object: bool,
        thinking: str | None,
        model: str | None,
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": model or self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if json_object:
            body["response_format"] = {"type": "json_object"}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if thinking and thinking != "disabled":
            body["thinking"] = {"type": thinking}

        data = json.dumps(body).encode("utf-8")

        keys_to_try = [self.api_key]
        if self._api_key_fallback:
            keys_to_try.append(self._api_key_fallback)

        t0 = time.monotonic()
        last_err: Exception | None = None
        last_err_detail: str = ""
        raw: str = ""
        for key_idx, api_key in enumerate(keys_to_try):
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }
            for attempt in range(self.max_retries + 1):
                req = urllib.request.Request(self.endpoint, data=data, method="POST", headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        raw = resp.read().decode("utf-8")
                    last_err = None
                    break
                except urllib.error.HTTPError as e:
                    if e.code in (429, 500, 502, 503, 504, 520, 521, 522, 524) and attempt < self.max_retries:
                        last_err = e
                        time.sleep(2.0 * (attempt + 1))
                        continue
                    last_err_detail = f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:500]}"
                    last_err = e
                    break
                except urllib.error.URLError as e:
                    last_err_detail = f"transport error: {e.reason}"
                    if attempt < self.max_retries:
                        last_err = e
                        time.sleep(2.0 * (attempt + 1))
                        continue
                    last_err = e
                except (http.client.IncompleteRead, http.client.RemoteDisconnected,
                        http.client.HTTPException, ConnectionError, TimeoutError) as e:
                    last_err_detail = f"connection error: {e}"
                    if attempt < self.max_retries:
                        last_err = e
                        time.sleep(2.0 * (attempt + 1))
                        continue
                    last_err = e
            if last_err is None:
                break
            if key_idx < len(keys_to_try) - 1:
                import sys
                print(f"[llm] primary key failed ({last_err_detail}), "
                      f"switching to fallback key", file=sys.stderr, flush=True)
                last_err = None
                continue
        if last_err is not None:
            raise LLMError(last_err_detail or f"provider unavailable: {last_err}") from last_err

        elapsed = time.monotonic() - t0
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            raise LLMError(f"bad JSON from provider: {raw[:200]}") from e

        self._record_usage(model or self.model, payload, elapsed)
        return payload

    def _record_usage(self, model: str, payload: dict[str, Any], elapsed: float) -> None:
        usage = payload.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        cached = 0
        details = usage.get("prompt_tokens_details") or {}
        if isinstance(details, dict):
            cached = int(details.get("cached_tokens") or 0)
        self.ledger.record(
            model,
            ModelUsage(
                input_tokens=max(prompt_tokens - cached, 0),
                cache_read_tokens=cached,
                cache_creation_tokens=0,
                output_tokens=completion_tokens,
                llm_requests=1,
                time_cost_sec=elapsed,
            ),
        )

    def chat_json(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        thinking: str | None = None,
        model: str | None = None,
    ) -> dict[str, Any]:
        """Return the assistant reply parsed as JSON (best effort).

        Does NOT use provider ``response_format`` (reasoning models such as
        deepseek-v4-pro burn the whole output budget on reasoning and return an
        empty ``content`` under that mode). Instead we rely on the prompt and a
        robust extractor, falling back to ``reasoning_content`` if ``content``
        is empty.
        """
        payload = self._request(
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            json_object=False,
            thinking=thinking,
            model=model,
        )
        message = _first_message(payload)
        content = message.get("content")
        if not content:
            content = message.get("reasoning_content") or ""
        if not content:
            raise LLMError(f"empty content in response: {json.dumps(payload)[:300]}")
        parsed = _extract_json(content)
        if parsed is None:
            raise LLMError(f"reply is not JSON: {str(content)[:300]}")
        return parsed

    def chat_text(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        thinking: str | None = None,
        model: str | None = None,
    ) -> str:
        payload = self._request(
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            json_object=False,
            thinking=thinking,
            model=model,
        )
        message = _first_message(payload)
        return message.get("content") or message.get("reasoning_content") or ""

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        thinking: str | None = None,
        model: str | None = None,
    ) -> dict[str, Any]:
        """Return the raw assistant message dict: {content, tool_calls?, reasoning_content?}.

        Retries once on empty response (no content and no tool_calls) which
        happens when DeepSeek stalls transiently.
        """
        for _empty_retry in range(2):
            payload = self._request(
                messages,
                max_tokens=max_tokens,
                temperature=temperature,
                json_object=False,
                thinking=thinking,
                model=model,
                tools=tools,
            )
            msg = _first_message(payload)
            has_content = bool(msg.get("content") or msg.get("reasoning_content"))
            has_tools = bool(msg.get("tool_calls"))
            if has_content or has_tools or _empty_retry > 0:
                return msg
            time.sleep(2.0)
        return msg


def _first_message(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull choices[0].message out of a completion, tolerating null entries.

    Providers occasionally return ``{"choices": [null]}`` or a null ``message``
    under load. The obvious ``(payload.get("choices") or [{}])[0].get(...)``
    raises AttributeError on those, because a list holding None is truthy so
    the fallback never fires.
    """
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return {}
    first = choices[0]
    if not isinstance(first, dict):
        return {}
    msg = first.get("message")
    return msg if isinstance(msg, dict) else {}


def tool_message(tool_call_id: str, content: str) -> dict[str, Any]:
    """Build a `role: tool` message responding to a tool call."""
    return {"role": "tool", "tool_call_id": tool_call_id, "content": content}


class MockLLM:
    """Scripted LLM for offline pipeline tests (no network, no key).

    Replays the provided JSON replies in order, repeating the last one forever.
    """

    def __init__(self, replies: list[dict], ledger: UsageLedger | None = None):
        self.replies = list(replies)
        self.i = 0
        self.ledger = ledger or UsageLedger()

    def chat_json(self, messages, *, max_tokens=4096, temperature=0.0, thinking=None, model=None) -> dict:
        reply = self.replies[min(self.i, len(self.replies) - 1)]
        self.i += 1
        self.ledger.record(
            model or "mock",
            ModelUsage(input_tokens=1, cache_read_tokens=0, cache_creation_tokens=0, output_tokens=1, llm_requests=1),
        )
        return reply

    def chat_text(self, messages, *, max_tokens=4096, temperature=0.0, thinking=None, model=None) -> str:
        return json.dumps(self.chat_json(messages, max_tokens=max_tokens, temperature=temperature, thinking=thinking, model=model))

    def chat(self, messages, *, tools=None, max_tokens=4096, temperature=0.0, thinking=None, model=None) -> dict:
        reply = self.replies[min(self.i, len(self.replies) - 1)]
        self.i += 1
        self.ledger.record(
            model or "mock",
            ModelUsage(input_tokens=1, cache_read_tokens=0, cache_creation_tokens=0, output_tokens=1, llm_requests=1),
        )
        return {"content": json.dumps(reply) if not isinstance(reply, str) else reply, "tool_calls": []}


def _extract_json(text: Any) -> dict | None:
    """Parse a JSON object out of free text, tolerating fences and prose."""
    if isinstance(text, dict):
        return text
    if not isinstance(text, str) or not text.strip():
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.lower().startswith("json"):
            t = t[4:]
        t = t.strip()
    try:
        out = json.loads(t)
        return out if isinstance(out, dict) else None
    except json.JSONDecodeError:
        pass
    start = t.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(t)):
        c = t[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    out = json.loads(t[start:i + 1])
                except json.JSONDecodeError:
                    return None
                return out if isinstance(out, dict) else None
    return None


def system(msg: str) -> dict[str, str]:
    return {"role": "system", "content": msg}


def user(msg: str) -> dict[str, str]:
    return {"role": "user", "content": msg}


def assistant(msg: str) -> dict[str, str]:
    return {"role": "assistant", "content": msg}


def estimate_cost(usage: ModelUsage, price_in: float | None, price_out: float | None) -> float | None:
    if price_in is None or price_out is None:
        return None
    total_in = usage.input_tokens + usage.cache_read_tokens + usage.cache_creation_tokens
    return (total_in / 1e6) * price_in + (usage.output_tokens / 1e6) * price_out


def validate_messages(messages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop empty contents and enforce role ordering robustness."""
    out = []
    for m in messages:
        role = m.get("role")
        content = m.get("content")
        if role not in ("system", "user", "assistant", "tool"):
            continue
        if content == "" or content is None:
            continue
        out.append({"role": role, "content": content})
    return out
