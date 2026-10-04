# core/provider_api.py
# The wire formats AgentalSec can speak to a model provider.
#
# Two styles, and nothing else in the app knows which one is active:
#
#   openai     chat/completions. DeepSeek, OpenAI, OpenRouter, Ollama, vLLM,
#              LiteLLM, and anything else that copied that shape.
#   anthropic  the native Messages API. Claude models, direct.
#
# The conversation is always HELD in the OpenAI shape (assistant tool_calls,
# role "tool" results), because that is what the rest of the app was built
# on. The anthropic style translates at the edge, per request, and translates
# the stream back into the same three chunk shapes run() already consumes.

import json
from urllib.parse import urlparse

STYLE_OPENAI    = "openai"
STYLE_ANTHROPIC = "anthropic"
STYLES          = (STYLE_OPENAI, STYLE_ANTHROPIC)

ANTHROPIC_VERSION = "2023-06-01"


def detect_style(api_url: str, configured: str = "auto") -> str:
    """
    Which wire format an endpoint speaks.

    An explicit setting wins. Otherwise it is read from the URL: the native
    Messages API ends in /messages, and api.anthropic.com is that API unless
    the path says it is the OpenAI compatibility layer.
    """
    want = (configured or "auto").strip().lower()
    if want in STYLES:
        return want
    url = (api_url or "").strip().lower().rstrip("/")
    if url.endswith("/messages"):
        return STYLE_ANTHROPIC
    host = urlparse(url if "://" in url else "https://" + url).netloc
    if host.endswith("anthropic.com") and "/chat/completions" not in url:
        return STYLE_ANTHROPIC
    return STYLE_OPENAI


def normalise_url(api_url: str, style: str) -> str:
    """A bare Anthropic base URL becomes the Messages endpoint."""
    url = (api_url or "").strip()
    if style != STYLE_ANTHROPIC or not url:
        return url
    base = url.rstrip("/")
    if base.endswith("/messages"):
        return base
    if base.endswith("/v1"):
        return base + "/messages"
    if urlparse(base if "://" in base else "https://" + base).path in ("", "/"):
        return base + "/v1/messages"
    return url


def auth_headers(style: str, key: str) -> dict:
    if style == STYLE_ANTHROPIC:
        return {"x-api-key": key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json"}
    return {"Authorization": f"Bearer {key}",
            "Content-Type": "application/json"}


def models_url(api_url: str) -> str:
    base = (api_url or "").rstrip("/")
    for tail in ("/chat/completions", "/completions", "/messages"):
        if base.endswith(tail):
            return base[: -len(tail)] + "/models"
    return base + "/models"


def style_label(style: str) -> str:
    return {STYLE_ANTHROPIC: "Anthropic Messages API"}.get(
        style, "OpenAI-compatible chat API")


def _loads(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        val = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return val if isinstance(val, dict) else {}


def to_anthropic_request(messages: list, tools: list, model: str,
                         max_tokens: int) -> dict:
    """
    OpenAI-shaped messages and tools to a Messages API request body.

    Rules the API enforces that the OpenAI shape does not: system is a
    top level field, roles must alternate, tool results ride in a user turn
    as tool_result blocks, and empty text blocks are rejected.
    """
    system_parts, out = [], []

    def _push(role, blocks):
        if not blocks:
            return
        if out and out[-1]["role"] == role:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": role, "content": list(blocks)})

    for m in messages:
        role = m.get("role")
        content = m.get("content")
        if role == "system":
            if content:
                system_parts.append(str(content))
        elif role == "user":
            if content:
                _push("user", [{"type": "text", "text": str(content)}])
        elif role == "assistant":
            blocks = []
            if content:
                blocks.append({"type": "text", "text": str(content)})
            for tc in (m.get("tool_calls") or []):
                fn = tc.get("function") or {}
                blocks.append({"type": "tool_use", "id": tc.get("id", ""),
                               "name": fn.get("name", ""),
                               "input": _loads(fn.get("arguments"))})
            _push("assistant", blocks)
        elif role == "tool":
            _push("user", [{"type": "tool_result",
                            "tool_use_id": m.get("tool_call_id", ""),
                            "content": str(content if content is not None else "")}])

    body = {
        "model":      model,
        "max_tokens": max_tokens,
        "messages":   out,
        "stream":     True,
    }
    if system_parts:
        body["system"] = "\n\n".join(system_parts)
    if tools:
        body["tools"] = [
            {"name": t["function"]["name"],
             "description": t["function"].get("description", ""),
             "input_schema": t["function"].get("parameters")
                             or {"type": "object", "properties": {}}}
            for t in tools]
        body["tool_choice"] = {"type": "auto"}
    return body


class AnthropicStream:
    """
    Folds Messages API stream events into what _stream_model yields.

    feed(event_dict) returns a list of (kind, value):
        ("text", str)             a visible answer token
        ("reasoning", None)       a thinking delta, counted and not shown
        ("usage", dict)           input_tokens / output_tokens so far
        ("stop", stop_reason)     the message ended
        ("error", str)            the provider reported an error
    Tool calls are collected in self.tool_calls as the same
    {index: {id, name, args}} dict the OpenAI path builds.
    """

    def __init__(self):
        self.tool_calls = {}
        self._block_kind = {}
        self.stop_reason = None
        self.input_tokens = 0
        self.output_tokens = 0

    def feed(self, ev: dict) -> list:
        out = []
        t = ev.get("type")
        if t == "message_start":
            u = (ev.get("message") or {}).get("usage") or {}
            self.input_tokens = int(u.get("input_tokens") or 0) \
                + int(u.get("cache_read_input_tokens") or 0) \
                + int(u.get("cache_creation_input_tokens") or 0)
            self.output_tokens = int(u.get("output_tokens") or 0)
            out.append(("usage", self.usage()))
        elif t == "content_block_start":
            idx = ev.get("index", 0)
            blk = ev.get("content_block") or {}
            kind = blk.get("type")
            self._block_kind[idx] = kind
            if kind == "tool_use":
                self.tool_calls[idx] = {"id": blk.get("id", ""),
                                        "name": blk.get("name", ""),
                                        "args": ""}
        elif t == "content_block_delta":
            idx = ev.get("index", 0)
            d = ev.get("delta") or {}
            dt = d.get("type")
            if dt == "text_delta" and d.get("text"):
                out.append(("text", d["text"]))
            elif dt == "input_json_delta" and idx in self.tool_calls:
                self.tool_calls[idx]["args"] += d.get("partial_json", "")
            elif dt in ("thinking_delta", "signature_delta"):
                out.append(("reasoning", None))
        elif t == "message_delta":
            d = ev.get("delta") or {}
            if d.get("stop_reason"):
                self.stop_reason = d["stop_reason"]
            u = ev.get("usage") or {}
            if u.get("output_tokens") is not None:
                self.output_tokens = int(u["output_tokens"])
            if u.get("input_tokens"):
                self.input_tokens = int(u["input_tokens"])
            out.append(("usage", self.usage()))
        elif t == "message_stop":
            out.append(("stop", self.stop_reason))
        elif t == "error":
            err = ev.get("error") or {}
            out.append(("error", f"{err.get('type', 'error')}: "
                                 f"{err.get('message', 'provider error')}"))
        return out

    def usage(self) -> dict:
        return {"prompt_tokens": self.input_tokens,
                "completion_tokens": self.output_tokens,
                "total_tokens": self.input_tokens + self.output_tokens}
