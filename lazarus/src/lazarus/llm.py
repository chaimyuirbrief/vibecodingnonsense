"""LLM providers behind one narrow interface: JSON-in-schema out.

Every LLM call in Lazarus is optional. The engine runs fully deterministic
without one (templates + rules + human review). When a provider is configured:

* ``AnthropicProvider`` uses the official SDK with structured outputs
  (``output_config.format``) and server-side refusal fallbacks.
* ``CachingProvider`` memoizes by (purpose, model, prompt, schema) in SQLite.
* ``BudgetedProvider`` hard-stops spend per process; over budget, calls return
  ``error="budget_exceeded"`` and callers degrade to the deterministic path.
* ``FakeLLM`` is a scripted test double with failure injection.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from .timeutil import ts

if TYPE_CHECKING:
    from .store import Store

# USD per million tokens (input, output). Source: Anthropic model table, cached 2026-10-06.
# Verify against current pricing before relying on cost numbers.
PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-fable-5-1": (10.00, 50.00),
}
# Models that accept server-side refusal fallbacks (fallbacks="default").
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}


@dataclass
class LLMResult:
    data: dict[str, Any] | None
    error: str | None = None
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cached: bool = False

    @property
    def cost_usd(self) -> float:
        if self.cached:
            return 0.0
        pin, pout = PRICING.get(self.model, (0.0, 0.0))
        return (self.input_tokens * pin + self.output_tokens * pout) / 1_000_000


class LLMProvider(Protocol):
    model: str

    def complete_json(self, *, purpose: str, system: str, user: str, schema: dict[str, Any],
                      max_tokens: int) -> LLMResult: ...


class AnthropicProvider:
    """Claude via the official ``anthropic`` SDK (optional dependency).

    Credentials resolve the SDK's usual way (ANTHROPIC_API_KEY, or an
    ``ant auth login`` profile). The SDK retries 408/409/429/5xx itself.
    """

    def __init__(self, model: str = "claude-opus-5-5", effort: str = "low", timeout: float = 30.0,
                 max_retries: int = 2, client: Any = None) -> None:
        if client is None:
            try:
                import anthropic
            except ImportError as e:  # pragma: no cover - exercised manually
                raise RuntimeError("pip install 'lazarus[llm]' (the anthropic SDK) to use AnthropicProvider") from e
            client = anthropic.Anthropic(timeout=timeout, max_retries=max_retries)
        self.client = client
        self.model = model
        self.effort = effort

    def complete_json(self, *, purpose: str, system: str, user: str, schema: dict[str, Any],
                      max_tokens: int) -> LLMResult:
        import anthropic

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user}],
            "output_config": {"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
            "metadata": {"user_id": f"lazarus-{purpose}"},
        }
        if self.model in _FALLBACK_MODELS:
            kwargs["betas"] = ["server-side-fallback-2026-07-01"]
            kwargs["fallbacks"] = "default"
        try:
            resp = self.client.beta.messages.create(**kwargs)
        except anthropic.RateLimitError:
            return LLMResult(None, "rate_limited", self.model)
        except anthropic.APITimeoutError:
            return LLMResult(None, "timeout", self.model)
        except anthropic.APIConnectionError:
            return LLMResult(None, "connection_error", self.model)
        except anthropic.APIStatusError as e:
            return LLMResult(None, f"api_error_{e.status_code}", self.model)

        usage = getattr(resp, "usage", None)
        it = int(getattr(usage, "input_tokens", 0) or 0)
        ot = int(getattr(usage, "output_tokens", 0) or 0)
        served = getattr(resp, "model", None) or self.model
        if resp.stop_reason == "refusal":
            return LLMResult(None, "refusal", served, it, ot)
        if resp.stop_reason == "max_tokens":
            return LLMResult(None, "truncated", served, it, ot)
        text = next((b.text for b in resp.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            return LLMResult(None, "no_text_block", served, it, ot)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return LLMResult(None, "invalid_json", served, it, ot)
        if not isinstance(data, dict):
            return LLMResult(None, "not_an_object", served, it, ot)
        return LLMResult(data, None, served, it, ot)


class CachingProvider:
    """Memoize deterministic-purpose calls (classification) in the store."""

    def __init__(self, inner: LLMProvider, store: Store, purposes: frozenset[str] = frozenset({"classify"})) -> None:
        self.inner = inner
        self.store = store
        self.purposes = purposes
        self.model = inner.model

    def complete_json(self, *, purpose: str, system: str, user: str, schema: dict[str, Any],
                      max_tokens: int) -> LLMResult:
        if purpose not in self.purposes:
            return self.inner.complete_json(purpose=purpose, system=system, user=user, schema=schema,
                                            max_tokens=max_tokens)
        key = hashlib.sha256(json.dumps([purpose, self.model, system, user, schema], sort_keys=True).encode()).hexdigest()
        row = self.store.conn.execute("SELECT value FROM llm_cache WHERE key=?", (key,)).fetchone()
        if row:
            return LLMResult(json.loads(row["value"]), None, self.model, cached=True)
        res = self.inner.complete_json(purpose=purpose, system=system, user=user, schema=schema, max_tokens=max_tokens)
        if res.data is not None and res.error is None:
            with self.store.tx():
                self.store.conn.execute("INSERT OR REPLACE INTO llm_cache (key, value, created_at) VALUES (?,?,?)",
                                        (key, json.dumps(res.data), ts(self.store.now())))
        return res


class BudgetExceeded(Exception):
    pass


class BudgetedProvider:
    """Hard spend ceiling + usage ledger. Thread-safe."""

    def __init__(self, inner: LLMProvider, max_usd: float, max_calls: int = 10_000, store: Store | None = None) -> None:
        self.inner = inner
        self.max_usd = max_usd
        self.max_calls = max_calls
        self.store = store
        self.model = inner.model
        self.spent_usd = 0.0
        self.calls = 0
        self._lock = threading.Lock()

    def complete_json(self, *, purpose: str, system: str, user: str, schema: dict[str, Any],
                      max_tokens: int) -> LLMResult:
        with self._lock:
            if self.calls >= self.max_calls or self.spent_usd >= self.max_usd:
                return LLMResult(None, "budget_exceeded", self.model)
            self.calls += 1
        res = self.inner.complete_json(purpose=purpose, system=system, user=user, schema=schema, max_tokens=max_tokens)
        with self._lock:
            self.spent_usd += res.cost_usd
        if self.store is not None and not res.cached:
            with self.store.tx():
                self.store.conn.execute(
                    "INSERT INTO llm_usage (ts, purpose, model, input_tokens, output_tokens, cost_usd, outcome) VALUES (?,?,?,?,?,?,?)",
                    (ts(self.store.now()), purpose, res.model or self.model, res.input_tokens, res.output_tokens,
                     res.cost_usd, res.error or "ok"),
                )
        return res


Handler = Callable[[str, str, str], dict[str, Any] | str | Exception]


class FakeLLM:
    """Scripted provider. ``handler(purpose, system, user)`` returns a dict (valid
    output), a str (raw text, e.g. malformed JSON), or an Exception (mapped to an
    error string). Token counts are synthetic: len(text)//4."""

    def __init__(self, handler: Handler, model: str = "fake-model") -> None:
        self.handler = handler
        self.model = model
        self.calls: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def complete_json(self, *, purpose: str, system: str, user: str, schema: dict[str, Any],
                      max_tokens: int) -> LLMResult:
        with self._lock:
            self.calls.append((purpose, user))
        it = (len(system) + len(user)) // 4
        out = self.handler(purpose, system, user)
        if isinstance(out, Exception):
            return LLMResult(None, type(out).__name__, self.model, it, 0)
        if isinstance(out, str):
            try:
                parsed = json.loads(out)
            except json.JSONDecodeError:
                return LLMResult(None, "invalid_json", self.model, it, len(out) // 4)
            if not isinstance(parsed, dict):
                return LLMResult(None, "not_an_object", self.model, it, len(out) // 4)
            out = parsed
        return LLMResult(out, None, self.model, it, len(json.dumps(out)) // 4)
