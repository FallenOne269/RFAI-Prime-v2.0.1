"""GovernedCouncil: the council wrapped in a policy screen, a budget and an evidence log.

Order of a run:
 1. log the configuration (code hashes, policy version and hash, budget, council switches);
 2. screen the input; a deny stops here and no model is called;
 3. run the council through a metered client, under a wall-clock limit;
 4. turn council signals into escalations (unresolved critics, unreadable critic replies,
    a failed verifier, truncated replies, a spent budget, a runtime error);
 5. screen the output; a deny withholds the text;
 6. log the decision and the outcome.

Failures are fail-safe: a spent budget or an error becomes ``review``, never ``allow``.
Council approval can only add caution. It never turns a review or deny into allow,
because the critics have not been shown to tell right answers from wrong ones.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import time
import uuid
from pathlib import Path
from typing import Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .. import rfai_prime_runtime as rt
from .budget import BudgetExhausted, ExecutionBudget, Meter, MeteredClient
from .evidence import ContentMode, EvidenceLog, _utc_now, content_ref
from .review import Outcome, ReviewRecord, outcome_of
from .safety_guard import GuardResult, SafetyGuard, escalate, flag

RUNTIME_VERSION = "2.1.0-governed-candidate"
Status = Literal["completed", "blocked_at_input", "budget_exhausted", "runtime_error"]


def code_hashes() -> dict[str, str]:
    root = Path(__file__).resolve().parents[1]
    files = [root / "rfai_prime_runtime.py"] + sorted((root / "governance").glob("*.py"))
    return {str(f.relative_to(root.parent)): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}


class JobContext(BaseModel):
    job_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    declared_domain: Optional[str] = None
    capabilities: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)


class GovernedResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    run_id: str
    status: Status
    guard: GuardResult
    outcome: Outcome
    final_text: Optional[str] = None
    withheld: bool = False
    usage: dict = Field(default_factory=dict)
    council: dict = Field(default_factory=dict)
    reviews: list[ReviewRecord] = Field(default_factory=list)
    evidence: EvidenceLog = Field(exclude=True)

    def release_text(self) -> str:
        """The answer, only once it may be released."""
        if self.outcome not in ("allowed", "approved_after_review") or self.final_text is None:
            raise PermissionError(f"text not releasable: outcome={self.outcome}")
        return self.final_text

    def summary(self) -> dict:
        d = self.model_dump(exclude={"final_text"})
        d["final_text_sha256"] = content_ref(self.final_text)["sha256"] if self.final_text else None
        d["evidence_head"] = self.evidence.head
        return d


def default_council_factory(**kw) -> Callable[[object], rt.RFAIPrimeCouncil]:
    def make(client):
        return rt.RFAIPrimeCouncil(client=client, **kw)
    return make


class GovernedCouncil:
    def __init__(
        self,
        client,
        guard: SafetyGuard,
        budget: ExecutionBudget = ExecutionBudget(),
        council_factory: Optional[Callable[[object], rt.RFAIPrimeCouncil]] = None,
        content_mode: ContentMode = "hash_only",
        max_unreadable_fraction: float = 0.34,
        clock: Callable[[], str] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.guard = guard
        self.budget = budget
        self.council_factory = council_factory or default_council_factory()
        self.content_mode = content_mode
        self.max_unreadable_fraction = max_unreadable_fraction
        self.clock = clock
        self.monotonic = monotonic

    def _ref(self, text: Optional[str]) -> dict:
        return content_ref(text, self.content_mode)

    async def run(self, task: str, ctx: Optional[JobContext] = None, run_id: Optional[str] = None) -> GovernedResult:
        ctx = ctx or JobContext()
        run_id = run_id or uuid.uuid4().hex
        log = EvidenceLog(run_id, clock=self.clock)
        meter = Meter(self.budget, clock=self.monotonic)
        meter.start()
        metered = MeteredClient(self.client, meter)
        council = self.council_factory(metered)
        p = self.guard.policy
        log.append("run_started", {
            "runtime_version": RUNTIME_VERSION,
            "code_sha256": code_hashes(),
            "policy": {"id": p.policy_id, "version": p.version, "sha256": p.sha256},
            "budget": dataclasses.asdict(self.budget),
            "council": {
                "architect_model": council.architect_model, "critic_model": council.critic_model,
                "integrator_model": council.integrator_model, "protocol": council.protocol,
                "max_revisions": council.max_revisions, "architect_plan": council.architect_plan,
                "strict_gate": council.strict_gate, "preserve_answer": council.preserve_answer,
                "verifier": getattr(council.verifier, "__name__", None) if council.verifier else None,
                "client": type(self.client).__name__,
            },
            "job": ctx.model_dump(),
            "content_mode": self.content_mode,
            "task": self._ref(task),
        })

        guard = GuardResult(policy_id=p.policy_id, policy_version=p.version, policy_sha256=p.sha256)
        status: Status = "completed"
        final_text: Optional[str] = None
        council_info: dict = {}

        # 1. input screen ---------------------------------------------------
        if len(task or "") > self.budget.max_input_chars:
            guard = escalate(guard, flag("deny", "medium", "INPUT_TOO_LARGE",
                                         f"task is {len(task)} chars, limit {self.budget.max_input_chars}",
                                         stage="input"))
        g_in = self.guard.evaluate(task, "input", ctx.capabilities, ctx.declared_domain, ctx.flags)
        guard = escalate(guard, g_in)
        log.append("input_screen", g_in.model_dump())

        if guard.decision == "deny":
            status = "blocked_at_input"
        else:
            # 2. council under budget ----------------------------------------
            resp = None
            try:
                resp = await asyncio.wait_for(council.invoke(task), timeout=self.budget.max_wall_seconds)
            except BudgetExhausted as e:
                status = "budget_exhausted"
                guard = escalate(guard, flag("review", "medium", "BUDGET_EXHAUSTED",
                                             f"run stopped at {e.limit} ({e.detail})", ["operator"]))
            except asyncio.TimeoutError:
                status = "budget_exhausted"
                guard = escalate(guard, flag("review", "medium", "BUDGET_EXHAUSTED",
                                             f"run stopped at max_wall_seconds ({self.budget.max_wall_seconds}s)",
                                             ["operator"]))
            except Exception as e:  # provider outage, bad reply shape, bug: fail safe
                status = "runtime_error"
                guard = escalate(guard, flag("review", "medium", "RUNTIME_ERROR",
                                             f"council run failed: {type(e).__name__}", ["operator"]))

            if resp is not None:
                tr = resp.trace
                for i, rnd in enumerate(tr.rounds):
                    log.append("council_round", {
                        "round": i, "draft": self._ref(rnd.draft),
                        "scores": {f.perspective: (f.score if f.readable else None) for f in rnd.feedbacks},
                        "mean_readable_score": rnd.mean_score, "approved": rnd.approved,
                        "verifier_ok": rnd.verifier_ok,
                    })
                n_replies = sum(len(r.feedbacks) for r in tr.rounds) or 1
                council_info = {"revisions": tr.revisions, "approved": tr.approved, "rounds": len(tr.rounds),
                                "unreadable_critic_replies": tr.unreadable_critic_replies,
                                "critic_replies": sum(len(r.feedbacks) for r in tr.rounds)}
                if not tr.approved:
                    guard = escalate(guard, flag("review", "low", "COUNCIL_UNRESOLVED",
                                                 "critics did not clear the approval gate within the revision budget",
                                                 ["reviewer"]))
                if tr.unreadable_critic_replies / n_replies >= self.max_unreadable_fraction:
                    guard = escalate(guard, flag("review", "low", "CRITIC_OUTPUT_UNREADABLE",
                                                 f"{tr.unreadable_critic_replies} of {n_replies} critic replies unreadable",
                                                 ["reviewer"]))
                if tr.rounds and tr.rounds[-1].verifier_ok is False:
                    guard = escalate(guard, flag("review", "medium", "VERIFIER_FAILED",
                                                 "the external check failed on the last draft", ["reviewer"]))
                if metered.truncated_replies:
                    guard = escalate(guard, flag("review", "low", "OUTPUT_TRUNCATED",
                                                 f"{metered.truncated_replies} model replies cut at max_output_chars",
                                                 ["reviewer"]))
                final_text = resp.final_text
                # 3. output screen -------------------------------------------
                g_out = self.guard.evaluate(final_text, "output", ctx.capabilities, ctx.declared_domain, ctx.flags)
                guard = escalate(guard, g_out)
                log.append("output_screen", {**g_out.model_dump(), "output": self._ref(final_text)})

        withheld = guard.decision == "deny" and final_text is not None
        if guard.decision == "deny":
            final_text = None
        outcome = outcome_of(guard.decision, guard.required_approvals, [])
        usage = {**meter.snapshot(), "truncated_replies": metered.truncated_replies}
        log.append("usage", usage)
        log.append("decision", {"status": status, "outcome": outcome, "withheld": withheld,
                                "guard": guard.model_dump()})
        return GovernedResult(run_id=run_id, status=status, guard=guard, outcome=outcome,
                              final_text=final_text, withheld=withheld, usage=usage,
                              council=council_info, evidence=log)
