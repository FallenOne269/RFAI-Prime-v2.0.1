"""Execution budgets. A spent budget stops the run; it never quietly keeps generating."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from ..rfai_prime_runtime import CouncilAbort


class BudgetExhausted(CouncilAbort):
    def __init__(self, limit: str, detail: str) -> None:
        super().__init__(f"{limit}: {detail}")
        self.limit = limit
        self.detail = detail


@dataclass(frozen=True)
class ExecutionBudget:
    max_input_chars: int = 20_000       # task text accepted for a run
    max_model_calls: int = 19           # v2.0.x worst case at max_revisions=2
    max_prompt_chars: int = 60_000      # any single prompt sent to a model
    max_output_chars: int = 40_000      # any single model reply kept
    max_wall_seconds: float = 600.0     # whole run

    def __post_init__(self) -> None:
        for name in ("max_input_chars", "max_model_calls", "max_prompt_chars", "max_output_chars"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not (isinstance(self.max_wall_seconds, (int, float)) and self.max_wall_seconds > 0):
            raise ValueError("max_wall_seconds must be positive")


@dataclass
class Meter:
    budget: ExecutionBudget
    clock: Callable[[], float] = time.monotonic
    calls: int = 0
    prompt_chars: int = 0
    output_chars: int = 0
    started: float = field(default=0.0)
    calls_by_role: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def start(self) -> None:
        self.started = self.clock()

    def elapsed(self) -> float:
        return self.clock() - self.started

    def before_call(self, role: str, prompt_chars: int) -> None:
        with self._lock:
            if self.elapsed() > self.budget.max_wall_seconds:
                raise BudgetExhausted("max_wall_seconds", f"{self.elapsed():.1f}s elapsed")
            if self.calls >= self.budget.max_model_calls:
                raise BudgetExhausted("max_model_calls", f"{self.calls} calls already made")
            if prompt_chars > self.budget.max_prompt_chars:
                raise BudgetExhausted("max_prompt_chars", f"prompt of {prompt_chars} chars")
            self.calls += 1
            self.prompt_chars += prompt_chars
            self.calls_by_role[role] = self.calls_by_role.get(role, 0) + 1

    def after_call(self, reply_chars: int) -> None:
        with self._lock:
            self.output_chars += reply_chars

    def snapshot(self) -> dict:
        return {"model_calls": self.calls, "prompt_chars": self.prompt_chars,
                "output_chars": self.output_chars, "calls_by_role": dict(self.calls_by_role),
                "elapsed_seconds": round(self.elapsed(), 3)}


def _role(prompt: str) -> str:
    head = prompt.split(" in the RFAI-PRIME council")[0]
    return head.replace("You are the ", "").strip()[:40] or "unknown"


class _Reply:
    def __init__(self, text: str) -> None:
        self.content = [type("Block", (), {"text": text})()]


class MeteredClient:
    """Wraps any client exposing .messages.create(model, max_tokens, messages).

    Every call is counted before it is made; a call over budget raises BudgetExhausted
    (a CouncilAbort) instead of reaching the provider. Replies longer than
    max_output_chars are cut and the cut is counted.
    """

    def __init__(self, inner, meter: Meter) -> None:
        self.inner = inner
        self.meter = meter
        self.messages = self
        self.truncated_replies = 0

    def create(self, model, max_tokens, messages):
        prompt = "".join(str(m.get("content", "")) for m in messages)
        self.meter.before_call(_role(prompt), len(prompt))
        resp = self.inner.messages.create(model=model, max_tokens=max_tokens, messages=messages)
        text = resp.content[0].text or ""
        if len(text) > self.meter.budget.max_output_chars:
            text = text[: self.meter.budget.max_output_chars]
            self.truncated_replies += 1
        self.meter.after_call(len(text))
        return _Reply(text)
